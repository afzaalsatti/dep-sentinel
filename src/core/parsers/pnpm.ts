import * as path from 'path';
import YAML from 'yaml';
import { GraphBuilder, sourceFromSpec } from '../graph';
import type { DependencyGraph } from '../types';

type DepMap = Record<string, string | { specifier?: string; version: string }>;

interface PnpmLock {
  lockfileVersion?: string | number;
  importers?: Record<string, { dependencies?: DepMap; devDependencies?: DepMap; optionalDependencies?: DepMap }>;
  dependencies?: DepMap;
  devDependencies?: DepMap;
  optionalDependencies?: DepMap;
  packages?: Record<string, PnpmPkg>;
  snapshots?: Record<string, PnpmPkg>;
}

interface PnpmPkg {
  name?: string;
  version?: string;
  resolution?: { integrity?: string; tarball?: string; type?: string; repo?: string };
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  dev?: boolean;
  requiresBuild?: boolean;
  hasBin?: boolean;
}

/** Remove peer-dependency suffixes: `1.0.0(react@18.2.0)` and v5 `1.0.0_react@18.2.0`. */
function stripPeers(v: string): string {
  return v.replace(/\(.*$/, '').replace(/_.*$/, '');
}

/** Parse a package id from the `packages`/`snapshots` section into [name, version]. */
function parseId(id: string, major: number): [string, string] | undefined {
  let s = id.startsWith('/') ? id.slice(1) : id;
  s = s.replace(/\(.*$/, '');
  if (major >= 6) {
    const at = s.lastIndexOf('@');
    if (at <= 0) return undefined;
    return [s.slice(0, at), stripPeers(s.slice(at + 1))];
  }
  const slash = s.lastIndexOf('/');
  if (slash <= 0) return undefined;
  return [s.slice(0, slash), stripPeers(s.slice(slash + 1))];
}

export function parsePnpmLock(file: string, text: string, includeDev: boolean): DependencyGraph {
  const lock = YAML.parse(text) as PnpmLock;
  const major = parseInt(String(lock.lockfileVersion ?? '5'), 10) || 5;
  const b = new GraphBuilder('npm', file, path.join(path.dirname(file), 'package.json'));

  const idToKey = new Map<string, string>(); // normalized "name@version" -> node key
  const norm = (name: string, version: string) => `${name}@${version}`;

  const meta = lock.packages ?? {};
  for (const [id, p] of Object.entries(meta)) {
    const parsed = parseId(id, major);
    const name = p.name ?? parsed?.[0];
    const version = p.version ?? parsed?.[1];
    if (!name || !version) continue;
    const res = p.resolution ?? {};
    const node = b.add(name, version, {
      dev: p.dev === true,
      integrity: res.integrity,
      resolved: res.tarball,
      hasInstallScript: p.requiresBuild,
      source: res.type === 'git' || res.repo ? 'git' : res.tarball ? sourceFromSpec(res.tarball) ?? 'url' : 'registry',
    });
    if (parsed) idToKey.set(norm(parsed[0], parsed[1]), node.key);
    idToKey.set(norm(name, version), node.key);
  }

  const refToKey = (depName: string, ref: string): string | undefined => {
    if (/^(link:|file:|workspace:)/.test(ref)) return undefined;
    let r = ref.startsWith('/') ? ref.slice(1) : ref;
    r = r.replace(/\(.*$/, '');
    // Alias: "string-width@4.2.3" or v5 "/string-width/4.2.3"
    if (!/^\d/.test(r)) {
      const parsed = parseId(r, major >= 6 || r.includes('@') ? 6 : 5);
      if (parsed) return idToKey.get(norm(parsed[0], parsed[1]));
    }
    return idToKey.get(norm(depName, stripPeers(r)));
  };

  const graphSection = lock.snapshots ?? lock.packages ?? {};
  for (const [id, p] of Object.entries(graphSection)) {
    const parsed = parseId(id, major);
    if (!parsed) continue;
    const from = idToKey.get(norm(parsed[0], parsed[1]));
    if (!from) continue;
    for (const [n, ref] of Object.entries({ ...p.dependencies, ...p.optionalDependencies })) {
      const to = refToKey(n, ref);
      if (to) b.edge(from, to);
    }
  }

  const addRoots = (deps: DepMap | undefined, dev: boolean) => {
    if (!deps || (dev && !includeDev)) return;
    for (const [n, v] of Object.entries(deps)) {
      const ref = typeof v === 'string' ? v : v.version;
      const k = refToKey(n, ref);
      if (k) b.root(k);
    }
  };
  if (lock.importers) {
    for (const imp of Object.values(lock.importers)) {
      addRoots(imp.dependencies, false);
      addRoots(imp.optionalDependencies, false);
      addRoots(imp.devDependencies, true);
    }
  } else {
    addRoots(lock.dependencies, false);
    addRoots(lock.optionalDependencies, false);
    addRoots(lock.devDependencies, true);
  }

  if (!includeDev) for (const [k, n] of b.nodes) if (n.dev) b.nodes.delete(k);
  return b.build();
}
