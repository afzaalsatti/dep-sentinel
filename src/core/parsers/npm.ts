import * as path from 'path';
import { GraphBuilder, sourceFromSpec } from '../graph';
import type { DependencyGraph } from '../types';

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

export function readPackageJson(text: string | undefined): PackageJson | undefined {
  if (!text) return undefined;
  try {
    return JSON.parse(text) as PackageJson;
  } catch {
    return undefined;
  }
}

export function directDeps(pkg: PackageJson | undefined, includeDev: boolean): Map<string, { range: string; dev: boolean }> {
  const out = new Map<string, { range: string; dev: boolean }>();
  if (!pkg) return out;
  for (const [n, r] of Object.entries(pkg.dependencies ?? {})) out.set(n, { range: r, dev: false });
  for (const [n, r] of Object.entries(pkg.optionalDependencies ?? {})) out.set(n, { range: r, dev: false });
  if (includeDev) for (const [n, r] of Object.entries(pkg.devDependencies ?? {})) if (!out.has(n)) out.set(n, { range: r, dev: true });
  return out;
}

/** Registry tarball URLs are normal; only git/file references in `resolved` change the source. */
export function sourceOf(resolved: string | undefined, version: string): ReturnType<typeof sourceFromSpec> {
  const fromVersion = sourceFromSpec(version);
  if (fromVersion) return fromVersion;
  const fromResolved = resolved ? sourceFromSpec(resolved) : undefined;
  return fromResolved === 'git' || fromResolved === 'file' ? fromResolved : 'registry';
}

interface LockEntryV2 {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  devOptional?: boolean;
  optional?: boolean;
  link?: boolean;
  hasInstallScript?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface LockEntryV1 {
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, LockEntryV1>;
}

/** package-lock.json / npm-shrinkwrap.json (lockfileVersion 1, 2, 3). */
export function parsePackageLock(file: string, text: string, packageJsonText: string | undefined, includeDev: boolean): DependencyGraph {
  const lock = JSON.parse(text) as {
    lockfileVersion?: number;
    packages?: Record<string, LockEntryV2>;
    dependencies?: Record<string, LockEntryV1>;
  };
  const manifest = path.join(path.dirname(file), 'package.json');
  const b = new GraphBuilder('npm', file, packageJsonText ? manifest : undefined);

  if (lock.packages && Object.keys(lock.packages).length > 0) {
    parseV2(b, lock.packages, includeDev);
  } else if (lock.dependencies) {
    parseV1(b, lock.dependencies, readPackageJson(packageJsonText), includeDev);
  }
  return b.build();
}

function nameFromPath(p: string, entry: LockEntryV2): string {
  const idx = p.lastIndexOf('node_modules/');
  if (idx >= 0) return p.slice(idx + 'node_modules/'.length);
  return entry.name ?? p;
}

function parseV2(b: GraphBuilder, packages: Record<string, LockEntryV2>, includeDev: boolean) {
  const keyOfPath = new Map<string, string>();

  const follow = (p: string): string => {
    const e = packages[p];
    if (e?.link && e.resolved && packages[e.resolved]) return e.resolved;
    return p;
  };

  // 1. Create nodes for every installed package.
  for (const [p, e] of Object.entries(packages)) {
    if (p === '' || e.link) continue;
    const isInstalled = p.includes('node_modules/');
    if (!isInstalled) continue; // workspace package sources are handled as roots below
    const dev = !!(e.dev || e.devOptional);
    if (dev && !includeDev) continue;
    const name = nameFromPath(p, e);
    const version = e.version ?? '0.0.0';
    const node = b.add(name, version, {
      dev,
      optional: e.optional,
      resolved: e.resolved,
      integrity: e.integrity,
      hasInstallScript: e.hasInstallScript,
      source: sourceOf(e.resolved, version),
    });
    keyOfPath.set(p, node.key);
  }

  const resolveDep = (fromPath: string, dep: string): string | undefined => {
    let base = fromPath;
    for (;;) {
      const candidate = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`;
      if (packages[candidate]) return follow(candidate);
      if (!base) return undefined;
      const idx = base.lastIndexOf('/node_modules/');
      base = idx >= 0 ? base.slice(0, idx) : base.startsWith('node_modules/') ? '' : '';
    }
  };

  const depsOf = (e: LockEntryV2, withDev: boolean) => ({
    ...(e.dependencies ?? {}),
    ...(e.optionalDependencies ?? {}),
    ...(withDev ? e.devDependencies ?? {} : {}),
  });

  // 2. Edges.
  for (const [p, key] of keyOfPath) {
    for (const dep of Object.keys(depsOf(packages[p], false))) {
      const target = resolveDep(p, dep);
      const tKey = target ? keyOfPath.get(target) : undefined;
      if (tKey) b.edge(key, tKey);
    }
  }

  // 3. Roots: the root project plus every workspace package.
  for (const [p, e] of Object.entries(packages)) {
    if (p.includes('node_modules/') || e.link) continue;
    for (const dep of Object.keys(depsOf(e, includeDev))) {
      const target = resolveDep(p, dep);
      const tKey = target ? keyOfPath.get(target) : undefined;
      if (tKey) b.root(tKey);
    }
  }
}

function parseV1(b: GraphBuilder, deps: Record<string, LockEntryV1>, pkg: PackageJson | undefined, includeDev: boolean) {
  type Scope = { parent?: Scope; entries: Record<string, LockEntryV1>; keys: Map<string, string> };

  const create = (entries: Record<string, LockEntryV1>, parent?: Scope): Scope => {
    const scope: Scope = { parent, entries, keys: new Map() };
    for (const [name, e] of Object.entries(entries)) {
      if (e.dev && !includeDev) continue;
      const node = b.add(name, e.version, {
        dev: !!e.dev,
        optional: e.optional,
        resolved: e.resolved,
        integrity: e.integrity,
        source: sourceOf(e.resolved, e.version),
      });
      scope.keys.set(name, node.key);
    }
    return scope;
  };

  const lookup = (scope: Scope | undefined, name: string): string | undefined => {
    for (let s = scope; s; s = s.parent) {
      const k = s.keys.get(name);
      if (k) return k;
    }
    return undefined;
  };

  const walk = (scope: Scope) => {
    for (const [name, e] of Object.entries(scope.entries)) {
      const key = scope.keys.get(name);
      if (!key) continue;
      const child = e.dependencies ? create(e.dependencies, scope) : undefined;
      for (const req of Object.keys(e.requires ?? {})) {
        const t = lookup(child ?? scope, req);
        if (t) b.edge(key, t);
      }
      if (child) walk(child);
    }
  };

  const top = create(deps);
  walk(top);
  if (pkg) {
    for (const name of directDeps(pkg, includeDev).keys()) {
      const k = top.keys.get(name);
      if (k) b.root(k);
    }
  }
}
