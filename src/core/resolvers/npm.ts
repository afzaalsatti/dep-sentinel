import * as semver from 'semver';
import { GraphBuilder, sourceFromSpec } from '../graph';
import { directDeps, readPackageJson } from '../parsers/npm';
import type { CoreContext, DependencyGraph } from '../types';

interface AbbrevPackument {
  'dist-tags'?: Record<string, string>;
  versions: Record<string, { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; hasInstallScript?: boolean; dist?: { tarball?: string; integrity?: string } }>;
}

export function encodeNpmName(name: string): string {
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

/** Resolve a package.json (no lockfile) against the registry – mirrors what a fresh `npm install` would pick. */
export async function resolvePackageJson(file: string, text: string, ctx: CoreContext): Promise<DependencyGraph> {
  const pkg = readPackageJson(text);
  const b = new GraphBuilder('npm', file, file);
  b.warnings.push('No lockfile found – versions were resolved against the registry (latest matching). Commit a lockfile for exact results.');
  if (!pkg) {
    b.warnings.push('package.json could not be parsed.');
    return b.build();
  }
  const registry = ctx.config.npmRegistry.replace(/\/$/, '');
  const overrides = new Map<string, string>();
  const raw = pkg as { overrides?: Record<string, unknown>; resolutions?: Record<string, unknown>; pnpm?: { overrides?: Record<string, unknown> } };
  for (const src of [raw.resolutions, raw.pnpm?.overrides, raw.overrides]) {
    for (const [k, v] of Object.entries(src ?? {})) if (typeof v === 'string' && !v.startsWith('$')) overrides.set(k, v);
  }
  const packuments = new Map<string, Promise<AbbrevPackument | undefined>>();
  const getPackument = (name: string) => {
    let p = packuments.get(name);
    if (!p) {
      p = (async () => {
        const cached = ctx.cache.get<AbbrevPackument>('npm-abbrev', name);
        if (cached) return cached;
        try {
          const doc = await ctx.http.jsonOrUndefined<AbbrevPackument>(`${registry}/${encodeNpmName(name)}`, {
            headers: { Accept: 'application/vnd.npm.install-v1+json' },
          });
          if (!doc) return undefined;
          // Keep only what we need to keep the cache small.
          const slim: AbbrevPackument = { 'dist-tags': doc['dist-tags'], versions: {} };
          for (const [v, m] of Object.entries(doc.versions ?? {})) {
            slim.versions[v] = { dependencies: m.dependencies, optionalDependencies: m.optionalDependencies, hasInstallScript: m.hasInstallScript, dist: m.dist ? { tarball: m.dist.tarball, integrity: m.dist.integrity } : undefined };
          }
          ctx.cache.set('npm-abbrev', name, slim, 6 * 3600_000);
          return slim;
        } catch (e) {
          ctx.log.warn(`npm packument ${name}: ${(e as Error).message}`);
          return undefined;
        }
      })();
      packuments.set(name, p);
    }
    return p;
  };

  type Item = { name: string; range: string; parent?: string; depth: number; dev: boolean };
  let level: Item[] = [...directDeps(pkg, ctx.config.includeDev)].map(([name, { range, dev }]) => ({ name, range, depth: 1, dev }));
  const resolvedSpec = new Map<string, string>();
  const failed: string[] = [];

  while (level.length && !ctx.isCancelled?.()) {
    const docs = await Promise.all(level.map((i) => (sourceFromSpec(i.range) ? Promise.resolve(undefined) : getPackument(aliasTarget(i).name))));
    const next: Item[] = [];
    level.forEach((item, idx) => {
      const spec = `${item.name}@${item.range}`;
      const link = (key: string) => {
        if (item.parent) b.edge(item.parent, key);
        else b.root(key);
        if (!item.dev) {
          const n = b.nodes.get(key);
          if (n) n.dev = false;
        }
      };
      const known = resolvedSpec.get(spec);
      if (known) return link(known);

      const src = sourceFromSpec(item.range);
      if (src) {
        const node = b.add(item.name, item.range, { source: src, dev: item.dev });
        resolvedSpec.set(spec, node.key);
        return link(node.key);
      }
      const { name, range } = aliasTarget(item);
      const doc = docs[idx];
      if (!doc) {
        failed.push(name);
        return;
      }
      const versions = Object.keys(doc.versions);
      let version = doc['dist-tags']?.[range] ?? semver.maxSatisfying(versions, range || '*', { loose: true }) ?? undefined;
      // Honour flat overrides / resolutions ("pkg" or "pkg@version" keys) like the package managers do.
      const forced = version ? overrides.get(`${name}@${version}`) ?? overrides.get(name) : undefined;
      if (forced) version = doc['dist-tags']?.[forced] ?? semver.maxSatisfying(versions, forced, { loose: true }) ?? version;
      if (!version) {
        failed.push(spec);
        return;
      }
      const manifest = doc.versions[version];
      const existed = b.nodes.has(`${name}@${version}`);
      const node = b.add(name, version, {
        dev: item.dev,
        resolved: manifest?.dist?.tarball,
        integrity: manifest?.dist?.integrity,
        hasInstallScript: manifest?.hasInstallScript,
        source: 'registry',
      });
      resolvedSpec.set(spec, node.key);
      link(node.key);
      if (existed || item.depth >= ctx.config.maxDepth || !ctx.config.resolveTransitive) return;
      for (const [n, r] of Object.entries({ ...manifest?.dependencies, ...manifest?.optionalDependencies })) {
        next.push({ name: n, range: r, parent: node.key, depth: item.depth + 1, dev: item.dev });
      }
    });
    if (b.nodes.size > 4000) {
      b.warnings.push('Dependency tree truncated at 4000 packages.');
      break;
    }
    level = next;
  }
  if (failed.length) b.warnings.push(`Could not resolve: ${[...new Set(failed)].slice(0, 8).join(', ')}`);
  return b.build();
}

function aliasTarget(item: { name: string; range: string }): { name: string; range: string } {
  if (item.range.startsWith('npm:')) {
    const spec = item.range.slice(4);
    const at = spec.indexOf('@', 1);
    return at < 0 ? { name: spec, range: '*' } : { name: spec.slice(0, at), range: spec.slice(at + 1) };
  }
  return item;
}
