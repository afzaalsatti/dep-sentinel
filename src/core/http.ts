export class HttpError extends Error {
  constructor(public readonly status: number, public readonly url: string, message?: string) {
    super(message ?? `HTTP ${status} for ${url}`);
  }
}

export interface RequestOptions {
  method?: 'GET' | 'POST';
  body?: unknown;
  headers?: Record<string, string>;
  timeoutMs?: number;
  retries?: number;
}

/** Simple concurrency limiter. */
export function createLimiter(concurrency: number) {
  let active = 0;
  const queue: (() => void)[] = [];
  const next = () => {
    if (active >= concurrency) return;
    const run = queue.shift();
    if (run) {
      active++;
      run();
    }
  };
  return function limit<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      queue.push(() => {
        fn()
          .then(resolve, reject)
          .finally(() => {
            active--;
            next();
          });
      });
      next();
    });
  };
}

const USER_AGENT = 'dep-sentinel/1.0 (+dependency security scanner)';
/** Upper bound for any response body (full npm packuments of huge packages are tens of MB). */
export const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * Only HTTPS is allowed (plain HTTP is accepted for localhost mirrors only). Data from these endpoints decides what
 * is reported as safe, so it must not be tamperable in transit.
 */
export function isAllowedUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' || (u.protocol === 'http:' && LOCAL_HOSTS.has(u.hostname));
  } catch {
    return false;
  }
}

const MAX_REDIRECTS = 5;

export class Http {
  private limit = createLimiter(12);

  constructor(private readonly maxBytes = MAX_RESPONSE_BYTES) {}

  /**
   * fetch with manual redirect handling: every hop is validated *before* it is requested, so a server can never
   * bounce us to plain HTTP or an internal address we would not have contacted directly.
   */
  private async fetchChecked(url: string, init: RequestInit): Promise<Response> {
    let current = url;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      if (!isAllowedUrl(current)) throw new Error(`Refusing non-HTTPS request to ${current}`);
      const res = await fetch(current, { ...init, redirect: 'manual', credentials: 'omit' });
      const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
      if (!location) return res;
      await res.body?.cancel().catch(() => undefined);
      const next = new URL(location, current).toString();
      if (!isAllowedUrl(next)) throw new Error(`Refusing redirect from ${current} to ${next}`);
      current = next;
    }
    throw new Error(`Refusing request: too many redirects for ${url}`);
  }

  async request(url: string, opts: RequestOptions = {}): Promise<Response> {
    if (!isAllowedUrl(url)) throw new Error(`Refusing non-HTTPS request to ${url}`);
    const retries = opts.retries ?? 2;
    let lastErr: unknown;
    for (let attempt = 0; attempt <= retries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 30000);
      try {
        const res = await this.limit(() =>
          this.fetchChecked(url, {
            method: opts.method ?? 'GET',
            headers: {
              'User-Agent': USER_AGENT,
              Accept: 'application/json',
              ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
              ...opts.headers,
            },
            body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
            signal: controller.signal,
          }),
        );
        if (res.status === 429 || res.status >= 500) {
          lastErr = new HttpError(res.status, url);
          await res.body?.cancel().catch(() => undefined);
          await delay(500 * 2 ** attempt);
          continue;
        }
        return res;
      } catch (e) {
        lastErr = e;
        if ((e as Error).message?.startsWith('Refusing')) break;
        if (attempt < retries) await delay(500 * 2 ** attempt);
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  /** Read a body with a hard size limit (protects against memory exhaustion by a hostile/broken server). */
  private async readText(res: Response, url: string): Promise<string> {
    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared > this.maxBytes) {
      await res.body?.cancel().catch(() => undefined);
      throw new Error(`Response too large (${declared} bytes) from ${url}`);
    }
    if (!res.body) return '';
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > this.maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error(`Response exceeded ${this.maxBytes} bytes from ${url}`);
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  async json<T>(url: string, opts: RequestOptions = {}): Promise<T> {
    const res = await this.request(url, opts);
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new HttpError(res.status, url);
    }
    return JSON.parse(await this.readText(res, url)) as T;
  }

  /** Returns undefined on 404 instead of throwing. */
  async jsonOrUndefined<T>(url: string, opts: RequestOptions = {}): Promise<T | undefined> {
    const res = await this.request(url, opts);
    if (res.status === 404) {
      await res.body?.cancel().catch(() => undefined);
      return undefined;
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new HttpError(res.status, url);
    }
    return JSON.parse(await this.readText(res, url)) as T;
  }

  async textOrUndefined(url: string, opts: RequestOptions = {}): Promise<string | undefined> {
    const res = await this.request(url, { ...opts, headers: { Accept: '*/*', ...opts.headers } });
    if (res.status === 404) {
      await res.body?.cancel().catch(() => undefined);
      return undefined;
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new HttpError(res.status, url);
    }
    return this.readText(res, url);
  }
}

export function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Return the URL only if it is a web link that is safe to open/render; otherwise undefined. */
export function safeExternalUrl(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}
