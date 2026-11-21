import { DependencyGraph, Ecosystem, PkgNode, pkgKey } from './types';

export class GraphBuilder {
  readonly nodes = new Map<string, PkgNode>();
  readonly roots = new Set<string>();
  readonly warnings: string[] = [];

  constructor(readonly ecosystem: Ecosystem, readonly file: string, readonly manifestFile?: string) {}

  add(name: string, version: string, extra: Partial<PkgNode> = {}): PkgNode {
    const key = pkgKey(name, version);
    let node = this.nodes.get(key);
    if (!node) {
      node = { key, name, version, deps: [], ...extra };
      this.nodes.set(key, node);
    } else {
      // A package is only "dev" if every occurrence is dev.
      if (extra.dev === false) node.dev = false;
      if (extra.hasInstallScript) node.hasInstallScript = true;
      if (!node.resolved && extra.resolved) node.resolved = extra.resolved;
      if (!node.integrity && extra.integrity) node.integrity = extra.integrity;
    }
    return node;
  }

  edge(from: string, to: string) {
    const node = this.nodes.get(from);
    if (node && from !== to && !node.deps.includes(to)) node.deps.push(to);
  }

  root(key: string) {
    this.roots.add(key);
  }

  build(): DependencyGraph {
    let roots = [...this.roots].filter((r) => this.nodes.has(r));
    if (roots.length === 0 && this.nodes.size > 0) {
      // No information about direct deps: treat nodes nobody depends on as direct.
      const incoming = new Set<string>();
      for (const n of this.nodes.values()) n.deps.forEach((d) => incoming.add(d));
      roots = [...this.nodes.keys()].filter((k) => !incoming.has(k));
    }
    // Drop edges to unknown nodes.
    for (const n of this.nodes.values()) n.deps = n.deps.filter((d) => this.nodes.has(d));
    return {
      ecosystem: this.ecosystem,
      file: this.file,
      manifestFile: this.manifestFile,
      nodes: this.nodes,
      roots,
      warnings: this.warnings,
    };
  }
}

export interface PathInfo {
  direct: boolean;
  via: string[];
  introducedBy?: string;
}

/** BFS from the roots to compute the shortest chain to every node. */
export function computePaths(graph: DependencyGraph): Map<string, PathInfo> {
  const parent = new Map<string, string | null>();
  const queue: string[] = [];
  for (const r of graph.roots) {
    if (!parent.has(r)) {
      parent.set(r, null);
      queue.push(r);
    }
  }
  while (queue.length) {
    const k = queue.shift()!;
    for (const d of graph.nodes.get(k)?.deps ?? []) {
      if (!parent.has(d)) {
        parent.set(d, k);
        queue.push(d);
      }
    }
  }
  const rootSet = new Set(graph.roots);
  const out = new Map<string, PathInfo>();
  for (const key of graph.nodes.keys()) {
    if (rootSet.has(key)) {
      out.set(key, { direct: true, via: [] });
      continue;
    }
    if (!parent.has(key)) {
      out.set(key, { direct: false, via: [] });
      continue;
    }
    const chain: string[] = [];
    let p = parent.get(key) ?? null;
    while (p) {
      chain.unshift(p);
      p = parent.get(p) ?? null;
    }
    out.set(key, { direct: false, via: chain, introducedBy: chain[0] });
  }
  return out;
}

export function sourceFromSpec(spec: string): PkgNode['source'] {
  if (/^(git\+|git:|github:|gitlab:|bitbucket:|git@)/.test(spec) || /\.git(#|$)/.test(spec)) return 'git';
  if (/^(file:|link:|\.\.?\/|\/)/.test(spec)) return 'file';
  if (/^workspace:/.test(spec)) return 'workspace';
  if (/^https?:/.test(spec)) return 'url';
  return undefined;
}
