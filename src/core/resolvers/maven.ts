import * as path from 'path';
import { XMLParser } from 'fast-xml-parser';
import { GraphBuilder } from '../graph';
import type { CoreContext, DependencyGraph } from '../types';

export interface MavenDep {
  groupId: string;
  artifactId: string;
  version?: string;
  scope?: string;
  type?: string;
  optional?: boolean;
  exclusions: string[]; // "g:a" (may contain *)
}

export interface RawPom {
  groupId?: string;
  artifactId: string;
  version?: string;
  parent?: { groupId: string; artifactId: string; version: string; relativePath?: string };
  properties: Record<string, string>;
  managed: MavenDep[];
  deps: MavenDep[];
}

interface EffectivePom {
  groupId: string;
  artifactId: string;
  version: string;
  props: Record<string, string>;
  managed: Map<string, MavenDep>;
  deps: MavenDep[];
}

const xml = new XMLParser({
  ignoreAttributes: true,
  parseTagValue: false,
  trimValues: true,
  isArray: (name) => name === 'dependency' || name === 'exclusion',
});

const str = (v: unknown): string | undefined => (v === undefined || v === null || v === '' ? undefined : String(v).trim());

function toDep(d: Record<string, unknown>): MavenDep {
  const exclusions = (((d.exclusions as Record<string, unknown>)?.exclusion as Record<string, unknown>[]) ?? []).map(
    (e) => `${str(e.groupId) ?? '*'}:${str(e.artifactId) ?? '*'}`,
  );
  return {
    groupId: str(d.groupId) ?? '',
    artifactId: str(d.artifactId) ?? '',
    version: str(d.version),
    scope: str(d.scope),
    type: str(d.type),
    optional: str(d.optional) === 'true',
    exclusions,
  };
}

export function parsePom(text: string): RawPom {
  const doc = xml.parse(text) as { project?: Record<string, unknown> };
  const p = doc.project ?? {};
  const parent = p.parent as Record<string, unknown> | undefined;
  const props: Record<string, string> = {};
  for (const [k, v] of Object.entries((p.properties as Record<string, unknown>) ?? {})) {
    if (typeof v !== 'object') props[k] = String(v ?? '');
  }
  const depList = (container: unknown) =>
    ((((container as Record<string, unknown>)?.dependencies as Record<string, unknown>)?.dependency as Record<string, unknown>[]) ?? []).map(toDep);
  return {
    groupId: str(p.groupId),
    artifactId: str(p.artifactId) ?? '',
    version: str(p.version),
    parent: parent
      ? {
          groupId: str(parent.groupId) ?? '',
          artifactId: str(parent.artifactId) ?? '',
          version: str(parent.version) ?? '',
          relativePath: parent.relativePath === undefined ? undefined : String(parent.relativePath ?? ''),
        }
      : undefined,
    properties: props,
    managed: depList(p.dependencyManagement),
    deps: depList(p),
  };
}

export function interpolate(s: string | undefined, props: Record<string, string>): string | undefined {
  if (s === undefined) return undefined;
  let out = s;
  for (let i = 0; i < 10 && out.includes('${'); i++) {
    const next = out.replace(/\$\{([^}]+)\}/g, (m, k: string) => props[k] ?? m);
    if (next === out) break;
    out = next;
  }
  return out;
}

/** Pick a concrete version from a Maven version or range. Ranges resolve to their lower bound (best effort). */
export function pickVersion(v: string | undefined): string | undefined {
  if (!v || v.includes('${')) return undefined;
  if (/^[\[(]/.test(v)) {
    const m = /^[\[(]\s*([^,\])]*)\s*(,|\])/.exec(v);
    const lower = m?.[1]?.trim();
    return lower || undefined;
  }
  return v;
}

const ga = (d: { groupId: string; artifactId: string }) => `${d.groupId}:${d.artifactId}`;

export interface RootItem {
  dep: MavenDep;
  dev: boolean;
}

export class MavenResolver {
  private memo = new Map<string, Promise<EffectivePom | undefined>>();
  readonly missing = new Set<string>();

  constructor(private readonly ctx: CoreContext) {}

  private async fetchRaw(g: string, a: string, v: string): Promise<RawPom | undefined> {
    const gav = `${g}:${a}:${v}`;
    const cached = this.ctx.cache.get<RawPom | null>('pom', gav);
    if (cached !== undefined) return cached ?? undefined;
    for (const repo of this.ctx.config.mavenRepos) {
      const url = `${repo.replace(/\/$/, '')}/${g.replace(/\./g, '/')}/${a}/${v}/${a}-${v}.pom`;
      try {
        const text = await this.ctx.http.textOrUndefined(url);
        if (text) {
          const raw = parsePom(text);
          this.ctx.cache.set('pom', gav, raw); // released POMs are immutable
          return raw;
        }
      } catch (e) {
        this.ctx.log.warn(`POM fetch failed ${url}: ${(e as Error).message}`);
        return undefined; // transient – don't cache negative
      }
    }
    this.ctx.cache.set('pom', gav, null, 24 * 3600_000);
    return undefined;
  }

  effective(g: string, a: string, v: string): Promise<EffectivePom | undefined> {
    const gav = `${g}:${a}:${v}`;
    let p = this.memo.get(gav);
    if (!p) {
      p = (async () => {
        const raw = await this.fetchRaw(g, a, v);
        if (!raw) {
          this.missing.add(gav);
          return undefined;
        }
        return this.effectiveFromRaw(raw, undefined, 0);
      })();
      this.memo.set(gav, p);
    }
    return p;
  }

  async effectiveFromRaw(raw: RawPom, localFile: string | undefined, depth: number): Promise<EffectivePom> {
    let parent: EffectivePom | undefined;
    if (raw.parent && depth < 15) {
      if (localFile && raw.parent.relativePath !== '') {
        let p = path.resolve(path.dirname(localFile), raw.parent.relativePath ?? '../pom.xml');
        if (!p.endsWith('.xml')) p = path.join(p, 'pom.xml');
        const text = await this.ctx.readFile(p);
        if (text) {
          try {
            const rp = parsePom(text);
            if (rp.artifactId === raw.parent.artifactId && (rp.groupId ?? rp.parent?.groupId) === raw.parent.groupId) {
              parent = await this.effectiveFromRaw(rp, p, depth + 1);
            }
          } catch {
            /* fall back to remote */
          }
        }
      }
      if (!parent) parent = await this.effective(raw.parent.groupId, raw.parent.artifactId, raw.parent.version);
    }

    const groupId = raw.groupId ?? raw.parent?.groupId ?? '';
    const version = raw.version ?? raw.parent?.version ?? '';
    const props: Record<string, string> = { ...(parent?.props ?? {}), ...raw.properties };
    Object.assign(props, {
      'project.groupId': groupId,
      'pom.groupId': groupId,
      groupId,
      'project.artifactId': raw.artifactId,
      'project.version': version,
      'pom.version': version,
      version,
    });
    if (raw.parent) {
      props['project.parent.version'] = raw.parent.version;
      props['parent.version'] = raw.parent.version;
      props['project.parent.groupId'] = raw.parent.groupId;
    }

    const interpDep = (d: MavenDep): MavenDep => ({
      ...d,
      groupId: interpolate(d.groupId, props) ?? d.groupId,
      artifactId: interpolate(d.artifactId, props) ?? d.artifactId,
      version: interpolate(d.version, props),
      scope: interpolate(d.scope, props),
    });

    const managed = new Map<string, MavenDep>(parent?.managed ?? []);
    const own = raw.managed.map(interpDep);
    const imports: MavenDep[] = [];
    for (const d of own) {
      if (d.scope === 'import' && (d.type ?? 'jar') === 'pom') imports.push(d);
      else managed.set(ga(d), d);
    }
    for (const imp of imports) {
      const v = pickVersion(imp.version);
      if (!v) continue;
      const bom = await this.effective(imp.groupId, imp.artifactId, v);
      for (const [k, d] of bom?.managed ?? []) if (!managed.has(k)) managed.set(k, d);
    }

    const deps = new Map<string, MavenDep>();
    for (const d of parent?.deps ?? []) deps.set(ga(d), d);
    for (const d of raw.deps.map(interpDep)) deps.set(ga(d), d);
    for (const [k, d] of deps) {
      const m = managed.get(k);
      if (m) {
        deps.set(k, {
          ...d,
          version: d.version ?? m.version,
          scope: d.scope ?? m.scope,
          exclusions: d.exclusions.length ? d.exclusions : m.exclusions,
        });
      }
    }
    return { groupId, artifactId: raw.artifactId, version, props, managed, deps: [...deps.values()] };
  }

  /** Resolve a project graph from root items (nearest-wins, like Maven). */
  async resolve(file: string, roots: RootItem[], rootManaged: Map<string, MavenDep>, maxDepth: number, b?: GraphBuilder): Promise<DependencyGraph> {
    b ??= new GraphBuilder('Maven', file, file);
    type Item = { dep: MavenDep; parentKey?: string; depth: number; dev: boolean; excl: string[] };
    let level: Item[] = roots.map((r) => ({ dep: r.dep, depth: 1, dev: r.dev, excl: r.dep.exclusions }));
    const resolved = new Map<string, string>();
    const unresolvedVersion: string[] = [];

    const excluded = (excl: string[], d: MavenDep) =>
      excl.some((e) => {
        const [g, a] = e.split(':');
        return (g === '*' || g === d.groupId) && (a === '*' || a === d.artifactId);
      });

    while (level.length && !this.ctx.isCancelled?.()) {
      const toExpand: { item: Item; key: string; version: string }[] = [];
      for (const item of level) {
        const id = ga(item.dep);
        const existing = resolved.get(id);
        if (existing) {
          if (item.parentKey) b.edge(item.parentKey, existing);
          else b.root(existing);
          if (!item.dev) {
            const n = b.nodes.get(existing);
            if (n) n.dev = false;
          }
          continue;
        }
        const managedVersion = item.depth > 1 ? rootManaged.get(id)?.version : undefined;
        const version = pickVersion(managedVersion ?? item.dep.version ?? rootManaged.get(id)?.version);
        if (!version) {
          if (item.depth === 1) unresolvedVersion.push(id);
          continue;
        }
        const node = b.add(id, version, { dev: item.dev, source: 'registry' });
        resolved.set(id, node.key);
        if (item.parentKey) b.edge(item.parentKey, node.key);
        else b.root(node.key);
        if (item.depth < maxDepth) toExpand.push({ item, key: node.key, version });
      }
      if (b.nodes.size > 3000) {
        b.warnings.push('Dependency tree truncated at 3000 artifacts.');
        break;
      }
      const effs = await Promise.all(toExpand.map((x) => this.effective(x.item.dep.groupId, x.item.dep.artifactId, x.version).catch(() => undefined)));
      const next: Item[] = [];
      toExpand.forEach((x, i) => {
        const eff = effs[i];
        if (!eff) return;
        for (const d of eff.deps) {
          const scope = d.scope ?? 'compile';
          if (scope !== 'compile' && scope !== 'runtime') continue;
          if (d.optional || !d.groupId || !d.artifactId) continue;
          if (excluded(x.item.excl, d)) continue;
          next.push({ dep: d, parentKey: x.key, depth: x.item.depth + 1, dev: x.item.dev, excl: [...x.item.excl, ...d.exclusions] });
        }
      });
      level = next;
    }

    if (unresolvedVersion.length) b.warnings.push(`Could not determine version for: ${unresolvedVersion.slice(0, 8).join(', ')}`);
    if (this.missing.size) {
      const list = [...this.missing];
      b.warnings.push(
        `${list.length} POM(s) not found in configured repositories (internal/private artifacts?) – their sub-dependencies are not included: ${list.slice(0, 5).join(', ')}${list.length > 5 ? '…' : ''}`,
      );
    }
    return b.build();
  }

  /** Resolve a local pom.xml. */
  async resolvePomFile(file: string, text: string, includeDev: boolean, maxDepth: number): Promise<DependencyGraph> {
    const raw = parsePom(text);
    const eff = await this.effectiveFromRaw(raw, file, 0);
    const roots: RootItem[] = [];
    for (const d of eff.deps) {
      const scope = d.scope ?? 'compile';
      if (scope === 'system' || scope === 'import') continue;
      const dev = scope === 'test';
      if (dev && !includeDev) continue;
      roots.push({ dep: d, dev });
    }
    return this.resolve(file, roots, eff.managed, maxDepth);
  }

  /** Expand a list of BOM coordinates into a managed-version map. */
  async bomManaged(boms: { groupId: string; artifactId: string; version: string }[]): Promise<Map<string, MavenDep>> {
    const out = new Map<string, MavenDep>();
    for (const bom of boms) {
      const eff = await this.effective(bom.groupId, bom.artifactId, bom.version);
      for (const [k, d] of eff?.managed ?? []) if (!out.has(k)) out.set(k, d);
    }
    return out;
  }
}
