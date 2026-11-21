import * as path from 'path';
import YAML from 'yaml';
import { GraphBuilder, sourceFromSpec } from '../graph';
import type { DependencyGraph } from '../types';
import { directDeps, readPackageJson, sourceOf } from './npm';

/** Split "name@range" respecting scoped names. */
export function splitSpec(spec: string): [string, string] {
  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  if (at < 0) return [spec, ''];
  return [spec.slice(0, at), spec.slice(at + 1)];
}

const unquote = (s: string) => s.trim().replace(/^"(.*)"$/, '$1');

export function parseYarnLock(file: string, text: string, packageJsonText: string | undefined, includeDev: boolean): DependencyGraph {
  const pkg = readPackageJson(packageJsonText);
  const manifest = packageJsonText ? path.join(path.dirname(file), 'package.json') : undefined;
  const b = new GraphBuilder('npm', file, manifest);
  if (/^__metadata:/m.test(text)) parseBerry(b, text, pkg, includeDev);
  else parseV1(b, text, pkg, includeDev);
  return b.build();
}

interface Block {
  specs: string[];
  version?: string;
  resolved?: string;
  integrity?: string;
  deps: Record<string, string>;
}

function parseV1(b: GraphBuilder, text: string, pkg: ReturnType<typeof readPackageJson>, includeDev: boolean) {
  const blocks: Block[] = [];
  let cur: Block | undefined;
  let inDeps = false;
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0 && line.endsWith(':')) {
      cur = { specs: line.slice(0, -1).split(',').map(unquote), deps: {} };
      blocks.push(cur);
      inDeps = false;
      continue;
    }
    if (!cur) continue;
    if (indent === 2) {
      inDeps = line === 'dependencies:' || line === 'optionalDependencies:';
      const m = /^"?([^"\s]+)"?\s+"?([^"]*)"?$/.exec(line);
      if (m && !line.endsWith(':')) {
        if (m[1] === 'version') cur.version = m[2];
        else if (m[1] === 'resolved') cur.resolved = m[2];
        else if (m[1] === 'integrity') cur.integrity = m[2];
      }
    } else if (indent >= 4 && inDeps) {
      const m = /^"?([^"\s]+)"?\s+"?([^"]*)"?$/.exec(line);
      if (m) cur.deps[m[1]] = m[2];
    }
  }

  const specToKey = new Map<string, string>();
  for (const blk of blocks) {
    if (!blk.version || blk.specs.length === 0) continue;
    const [name, range] = splitSpec(blk.specs[0]);
    const node = b.add(name, blk.version, {
      resolved: blk.resolved,
      integrity: blk.integrity,
      source: sourceFromSpec(range) ?? sourceOf(blk.resolved, blk.version),
    });
    for (const s of blk.specs) specToKey.set(s, node.key);
  }
  for (const blk of blocks) {
    if (!blk.version) continue;
    const from = specToKey.get(blk.specs[0]);
    if (!from) continue;
    for (const [n, r] of Object.entries(blk.deps)) {
      const to = specToKey.get(`${n}@${r}`);
      if (to) b.edge(from, to);
    }
  }
  markRoots(b, specToKey, pkg, includeDev);
}

function markRoots(b: GraphBuilder, specToKey: Map<string, string>, pkg: ReturnType<typeof readPackageJson>, includeDev: boolean) {
  const direct = directDeps(pkg, true);
  for (const [n, { range, dev }] of direct) {
    const k = specToKey.get(`${n}@${range}`) ?? specToKey.get(`${n}@npm:${range}`);
    if (!k) continue;
    const node = b.nodes.get(k);
    if (node && dev) node.dev = true;
    if (!dev || includeDev) b.root(k);
  }
  propagateDev(b);
  if (!includeDev) {
    for (const [k, n] of b.nodes) if (n.dev) b.nodes.delete(k);
  }
}

/** Mark nodes reachable only from dev roots as dev. */
export function propagateDev(b: GraphBuilder) {
  const prodReach = new Set<string>();
  const stack = [...b.roots].filter((r) => !b.nodes.get(r)?.dev);
  while (stack.length) {
    const k = stack.pop()!;
    if (prodReach.has(k)) continue;
    prodReach.add(k);
    b.nodes.get(k)?.deps.forEach((d) => stack.push(d));
  }
  if (b.roots.size === 0) return;
  for (const [k, n] of b.nodes) n.dev = !prodReach.has(k);
}

function parseBerry(b: GraphBuilder, text: string, pkg: ReturnType<typeof readPackageJson>, includeDev: boolean) {
  const doc = YAML.parse(text) as Record<string, { version?: string; resolution?: string; checksum?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; linkType?: string }>;
  const specToKey = new Map<string, string>();
  const workspaceEntries: (typeof doc)[string][] = [];
  for (const [specs, e] of Object.entries(doc)) {
    if (specs === '__metadata' || !e?.version) continue;
    const list = specs.split(',').map((s) => s.trim());
    const resolution = e.resolution ?? list[0];
    if (/@workspace:/.test(resolution)) {
      workspaceEntries.push(e);
      continue;
    }
    const [name, ref] = splitSpec(resolution);
    const node = b.add(name, e.version, {
      integrity: e.checksum,
      source: ref.startsWith('npm:') ? 'registry' : sourceFromSpec(ref.replace(/^(patch:|portal:)/, '')) ?? 'unknown',
    });
    for (const s of list) specToKey.set(s, node.key);
  }
  const lookup = (n: string, r: string) => specToKey.get(`${n}@${r}`) ?? specToKey.get(`${n}@npm:${r}`);
  for (const [specs, e] of Object.entries(doc)) {
    if (specs === '__metadata' || !e?.version) continue;
    const from = specToKey.get(specs.split(',')[0].trim());
    if (!from) continue;
    for (const [n, r] of Object.entries({ ...e.dependencies, ...e.optionalDependencies })) {
      const to = lookup(n, r);
      if (to) b.edge(from, to);
    }
  }
  if (pkg) {
    markRoots(b, specToKey, pkg, includeDev);
  } else {
    for (const ws of workspaceEntries) {
      for (const [n, r] of Object.entries({ ...ws.dependencies, ...ws.optionalDependencies })) {
        const k = lookup(n, r);
        if (k) b.root(k);
      }
    }
  }
}
