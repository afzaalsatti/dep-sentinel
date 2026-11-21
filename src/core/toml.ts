/**
 * Minimal TOML parser sufficient for lockfiles and manifests
 * (Cargo.lock, poetry.lock, uv.lock, pyproject.toml, Pipfile, libs.versions.toml).
 * Supports: [tables], [[array tables]], dotted/quoted keys, basic & literal strings,
 * multi-line strings, numbers, booleans, dates (as strings), arrays (multi-line) and inline tables.
 */
export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;
export interface TomlTable {
  [key: string]: TomlValue;
}

/** Null-prototype table: keys can never reach Object.prototype. */
function newTable(): TomlTable {
  return Object.create(null) as TomlTable;
}

const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Reject keys used for prototype-pollution attacks (no legitimate lockfile/manifest uses them). */
function safeKey(k: string): string {
  if (UNSAFE_KEYS.has(k)) throw new Error(`Unsafe TOML key "${k}"`);
  return k;
}

export function parseToml(src: string): TomlTable {
  const p = new Parser(src);
  return p.parse();
}

class Parser {
  private i = 0;
  private root: TomlTable = newTable();
  private current: TomlTable = this.root;

  constructor(private readonly s: string) {}

  parse(): TomlTable {
    while (this.i < this.s.length) {
      this.skipWsAndComments(true);
      if (this.i >= this.s.length) break;
      const c = this.s[this.i];
      if (c === '[') {
        this.parseHeader();
      } else {
        this.parseKeyValue(this.current);
      }
    }
    return this.root;
  }

  private parseHeader() {
    const isArray = this.s.startsWith('[[', this.i);
    this.i += isArray ? 2 : 1;
    this.skipInlineWs();
    const keys = this.parseKeyPath();
    this.skipInlineWs();
    this.i += isArray ? 2 : 1;
    let table = this.root;
    for (let k = 0; k < keys.length; k++) {
      const key = keys[k];
      const last = k === keys.length - 1;
      if (last && isArray) {
        const arr = (table[key] as TomlValue[] | undefined) ?? [];
        if (!Array.isArray(table[key])) table[key] = arr;
        const t: TomlTable = newTable();
        arr.push(t);
        table = t;
      } else {
        let next = table[key];
        if (next === undefined) {
          next = newTable();
          table[key] = next;
        }
        if (Array.isArray(next)) next = next[next.length - 1] as TomlTable;
        table = next as TomlTable;
      }
    }
    this.current = table;
    this.skipToEol();
  }

  private parseKeyValue(target: TomlTable) {
    const keys = this.parseKeyPath();
    this.skipInlineWs();
    if (this.s[this.i] !== '=') {
      // malformed line – skip it
      this.skipToEol();
      return;
    }
    this.i++;
    this.skipInlineWs();
    const value = this.parseValue();
    let t = target;
    for (let k = 0; k < keys.length - 1; k++) {
      if (typeof t[keys[k]] !== 'object' || Array.isArray(t[keys[k]])) t[keys[k]] = newTable();
      t = t[keys[k]] as TomlTable;
    }
    t[keys[keys.length - 1]] = value;
  }

  private parseKeyPath(): string[] {
    const keys: string[] = [];
    for (;;) {
      this.skipInlineWs();
      const c = this.s[this.i];
      if (c === '"') keys.push(safeKey(this.parseBasicString()));
      else if (c === "'") keys.push(safeKey(this.parseLiteralString()));
      else {
        const start = this.i;
        while (this.i < this.s.length && /[A-Za-z0-9_\-]/.test(this.s[this.i])) this.i++;
        keys.push(safeKey(this.s.slice(start, this.i)));
      }
      this.skipInlineWs();
      if (this.s[this.i] === '.') {
        this.i++;
        continue;
      }
      return keys;
    }
  }

  private parseValue(): TomlValue {
    const c = this.s[this.i];
    if (c === '"') {
      if (this.s.startsWith('"""', this.i)) return this.parseMultiline('"""');
      return this.parseBasicString();
    }
    if (c === "'") {
      if (this.s.startsWith("'''", this.i)) return this.parseMultiline("'''");
      return this.parseLiteralString();
    }
    if (c === '[') return this.parseArray();
    if (c === '{') return this.parseInlineTable();
    const start = this.i;
    while (this.i < this.s.length && !/[,\]\}\r\n#]/.test(this.s[this.i])) this.i++;
    const raw = this.s.slice(start, this.i).trim();
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    if (/^[+-]?\d[\d_]*(\.\d+)?([eE][+-]?\d+)?$/.test(raw)) return Number(raw.replace(/_/g, ''));
    return raw;
  }

  private parseArray(): TomlValue[] {
    this.i++;
    const out: TomlValue[] = [];
    for (;;) {
      this.skipWsAndComments(true);
      if (this.s[this.i] === ']') {
        this.i++;
        return out;
      }
      if (this.i >= this.s.length) return out;
      out.push(this.parseValue());
      this.skipWsAndComments(true);
      if (this.s[this.i] === ',') this.i++;
    }
  }

  private parseInlineTable(): TomlTable {
    this.i++;
    const t: TomlTable = newTable();
    for (;;) {
      this.skipWsAndComments(true);
      if (this.s[this.i] === '}') {
        this.i++;
        return t;
      }
      if (this.i >= this.s.length) return t;
      this.parseKeyValue(t);
      this.skipWsAndComments(true);
      if (this.s[this.i] === ',') this.i++;
    }
  }

  private parseBasicString(): string {
    this.i++;
    let out = '';
    while (this.i < this.s.length && this.s[this.i] !== '"') {
      if (this.s[this.i] === '\\') {
        const n = this.s[this.i + 1];
        const map: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', b: '\b', f: '\f' };
        if (n === 'u' || n === 'U') {
          const len = n === 'u' ? 4 : 8;
          out += String.fromCodePoint(parseInt(this.s.substr(this.i + 2, len), 16));
          this.i += 2 + len;
          continue;
        }
        out += map[n] ?? n;
        this.i += 2;
        continue;
      }
      out += this.s[this.i++];
    }
    this.i++;
    return out;
  }

  private parseLiteralString(): string {
    this.i++;
    const end = this.s.indexOf("'", this.i);
    const out = this.s.slice(this.i, end < 0 ? undefined : end);
    this.i = end < 0 ? this.s.length : end + 1;
    return out;
  }

  private parseMultiline(delim: string): string {
    this.i += 3;
    const end = this.s.indexOf(delim, this.i);
    let out = this.s.slice(this.i, end < 0 ? undefined : end);
    this.i = end < 0 ? this.s.length : end + 3;
    if (out.startsWith('\r\n')) out = out.slice(2);
    else if (out.startsWith('\n')) out = out.slice(1);
    return out;
  }

  private skipInlineWs() {
    while (this.s[this.i] === ' ' || this.s[this.i] === '\t') this.i++;
  }

  private skipWsAndComments(newlines: boolean) {
    for (;;) {
      const c = this.s[this.i];
      if (c === ' ' || c === '\t' || (newlines && (c === '\n' || c === '\r'))) this.i++;
      else if (c === '#') this.skipToEol();
      else return;
    }
  }

  private skipToEol() {
    while (this.i < this.s.length && this.s[this.i] !== '\n') this.i++;
  }
}
