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

const USER_AGENT = 'dep-sentinel-vscode/0.1 (+dependency security scanner)';

export class Http {
  private limit = createLimiter(12);

  async request(url: string, opts: RequestOptions = {}): Promise<Response> {
    const retries = opts.retries ?? 2;
    let lastErr: unknown;
    for (let attempt = 0; attempt <= retries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 30000);
      try {
        const res = await this.limit(() =>
          fetch(url, {
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
          await delay(500 * 2 ** attempt);
          continue;
        }
        return res;
      } catch (e) {
        lastErr = e;
        if (attempt < retries) await delay(500 * 2 ** attempt);
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  async json<T>(url: string, opts: RequestOptions = {}): Promise<T> {
    const res = await this.request(url, opts);
    if (!res.ok) throw new HttpError(res.status, url);
    return (await res.json()) as T;
  }

  /** Returns undefined on 404 instead of throwing. */
  async jsonOrUndefined<T>(url: string, opts: RequestOptions = {}): Promise<T | undefined> {
    const res = await this.request(url, opts);
    if (res.status === 404) return undefined;
    if (!res.ok) throw new HttpError(res.status, url);
    return (await res.json()) as T;
  }

  async textOrUndefined(url: string, opts: RequestOptions = {}): Promise<string | undefined> {
    const res = await this.request(url, { ...opts, headers: { Accept: '*/*', ...opts.headers } });
    if (res.status === 404) return undefined;
    if (!res.ok) throw new HttpError(res.status, url);
    return res.text();
  }
}

export function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}
