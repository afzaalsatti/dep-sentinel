import { promises as fs } from 'fs';
import * as path from 'path';
import type { Cache } from './types';

interface Entry {
  v: unknown;
  /** Expiry epoch ms; 0 = never expires. */
  e: number;
}

/**
 * Namespaced JSON file cache. Each namespace is stored in its own file and
 * loaded lazily. Writes are debounced.
 */
export class FileCache implements Cache {
  private data = new Map<string, Map<string, Entry>>();
  private dirty = new Set<string>();
  private timer: NodeJS.Timeout | undefined;

  constructor(private readonly dir: string) {}

  /** Must be called before use so namespaces are available synchronously. */
  async load(namespaces: string[]): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true });
    const now = Date.now();
    for (const ns of namespaces) {
      const map = new Map<string, Entry>();
      try {
        const raw = JSON.parse(await fs.readFile(this.file(ns), 'utf8')) as Record<string, Entry>;
        for (const [k, entry] of Object.entries(raw)) {
          if (entry.e === 0 || entry.e > now) map.set(k, entry);
        }
      } catch {
        /* missing or corrupt cache file */
      }
      this.data.set(ns, map);
    }
  }

  get<T>(ns: string, key: string): T | undefined {
    const entry = this.ns(ns).get(key);
    if (!entry) return undefined;
    if (entry.e !== 0 && entry.e < Date.now()) {
      this.ns(ns).delete(key);
      return undefined;
    }
    return entry.v as T;
  }

  set<T>(ns: string, key: string, value: T, ttlMs?: number): void {
    this.ns(ns).set(key, { v: value, e: ttlMs ? Date.now() + ttlMs : 0 });
    this.dirty.add(ns);
    if (!this.timer) this.timer = setTimeout(() => void this.flush(), 5000);
  }

  async flush(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    const pending = [...this.dirty];
    this.dirty.clear();
    await fs.mkdir(this.dir, { recursive: true });
    for (const ns of pending) {
      const obj = Object.fromEntries(this.ns(ns));
      await fs.writeFile(this.file(ns), JSON.stringify(obj), 'utf8');
    }
  }

  async clear(): Promise<void> {
    for (const ns of this.data.keys()) {
      this.data.set(ns, new Map());
      await fs.rm(this.file(ns), { force: true });
    }
    this.dirty.clear();
  }

  private ns(ns: string): Map<string, Entry> {
    let map = this.data.get(ns);
    if (!map) {
      map = new Map();
      this.data.set(ns, map);
    }
    return map;
  }

  private file(ns: string) {
    return path.join(this.dir, `${ns.replace(/[^a-z0-9_-]/gi, '_')}.json`);
  }
}

/** In-memory cache (used in tests). */
export class MemoryCache implements Cache {
  private m = new Map<string, Entry>();
  get<T>(ns: string, key: string): T | undefined {
    const e = this.m.get(`${ns}\u0000${key}`);
    if (!e || (e.e !== 0 && e.e < Date.now())) return undefined;
    return e.v as T;
  }
  set<T>(ns: string, key: string, value: T, ttlMs?: number): void {
    this.m.set(`${ns}\u0000${key}`, { v: value, e: ttlMs ? Date.now() + ttlMs : 0 });
  }
  async clear() {
    this.m.clear();
  }
  async flush() {}
}
