import * as path from 'path';
import { GraphBuilder } from '../graph';
import { parseToml, TomlTable } from '../toml';
import type { DependencyGraph } from '../types';

/** go.mod – Go >= 1.17 lists every module needed for the build (with `// indirect`). */
export function parseGoMod(file: string, text: string): DependencyGraph {
  const b = new GraphBuilder('Go', file, file);
  let inBlock = false;
  const replaced: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^require\s*\($/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ')') {
      inBlock = false;
      continue;
    }
    let spec: string | undefined;
    if (inBlock) spec = line;
    else if (line.startsWith('require ')) spec = line.slice(8).trim();
    else if (line.startsWith('replace ')) replaced.push(line.slice(8).trim());
    if (!spec || spec.startsWith('//')) continue;
    const m = /^(\S+)\s+(v\S+)(\s*\/\/\s*indirect)?/.exec(spec);
    if (!m) continue;
    const node = b.add(m[1], m[2].replace(/^v/, ''), { source: 'registry' });
    if (!m[3]) b.root(node.key);
  }
  for (const r of replaced) {
    const m = /^(\S+)(?:\s+\S+)?\s+=>\s+(\S+)/.exec(r);
    if (m && /^\.{0,2}\//.test(m[2])) b.warnings.push(`Module ${m[1]} is replaced with local path ${m[2]}.`);
  }
  // go.mod has no edges: indirect modules are reported as transitive with unknown path.
  return b.build();
}

/** Cargo.lock */
export function parseCargoLock(file: string, text: string): DependencyGraph {
  const t = parseToml(text);
  const b = new GraphBuilder('crates.io', file, path.join(path.dirname(file), 'Cargo.toml'));
  const pkgs = (t.package as TomlTable[] | undefined) ?? [];
  const byName = new Map<string, string[]>(); // name -> keys
  const members: TomlTable[] = [];
  for (const p of pkgs) {
    const source = typeof p.source === 'string' ? p.source : undefined;
    if (!source) {
      members.push(p);
      continue;
    }
    const node = b.add(String(p.name), String(p.version), {
      source: source.startsWith('git+') ? 'git' : 'registry',
      resolved: source.replace(/^registry\+/, ''),
      integrity: typeof p.checksum === 'string' ? p.checksum : undefined,
    });
    byName.set(node.name, [...(byName.get(node.name) ?? []), node.key]);
  }
  const resolve = (spec: string): string | undefined => {
    const [name, version] = spec.split(' ');
    const keys = byName.get(name);
    if (!keys) return undefined;
    if (!version) return keys[0];
    return keys.find((k) => k === `${name}@${version}`) ?? keys[0];
  };
  for (const p of pkgs) {
    const from = typeof p.source === 'string' ? `${p.name}@${p.version}` : undefined;
    for (const d of (p.dependencies as string[] | undefined) ?? []) {
      const to = resolve(d);
      if (!to) continue;
      if (from) b.edge(from, to);
      else b.root(to);
    }
  }
  return b.build();
}

/** Gemfile.lock */
export function parseGemfileLock(file: string, text: string): DependencyGraph {
  const b = new GraphBuilder('RubyGems', file, path.join(path.dirname(file), 'Gemfile'));
  let section = '';
  let current: string | undefined;
  const pending: [string, string][] = [];
  const keyByName = new Map<string, string>();
  for (const raw of text.split(/\r?\n/)) {
    if (/^[A-Z]/.test(raw)) {
      section = raw.trim();
      continue;
    }
    if (section === 'GEM' || section === 'GIT' || section === 'PATH') {
      const spec = /^ {4}([^\s(]+) \(([^)]+)\)$/.exec(raw);
      if (spec) {
        const version = spec[2].replace(/-(x86|x64|arm|aarch64|java|universal|mingw|mswin|darwin|linux)[\w-]*$/, '');
        const node = b.add(spec[1], version, { source: section === 'GEM' ? 'registry' : section === 'GIT' ? 'git' : 'file' });
        keyByName.set(spec[1], node.key);
        current = node.key;
        continue;
      }
      const dep = /^ {6}([^\s(]+)/.exec(raw);
      if (dep && current) pending.push([current, dep[1]]);
    } else if (section === 'DEPENDENCIES') {
      const m = /^ {2}([^\s(!]+)/.exec(raw);
      if (m) {
        const k = keyByName.get(m[1]);
        if (k) b.root(k);
        else pending.push(['__root__', m[1]]);
      }
    }
  }
  for (const [from, name] of pending) {
    const to = keyByName.get(name);
    if (!to) continue;
    if (from === '__root__') b.root(to);
    else b.edge(from, to);
  }
  return b.build();
}

/** composer.lock */
export function parseComposerLock(file: string, text: string, composerJsonText: string | undefined, includeDev: boolean): DependencyGraph {
  const lock = JSON.parse(text) as Record<string, { name: string; version: string; require?: Record<string, string>; source?: { type?: string; url?: string }; dist?: { url?: string; shasum?: string } }[]>;
  const composerJson = path.join(path.dirname(file), 'composer.json');
  const b = new GraphBuilder('Packagist', file, composerJsonText ? composerJson : undefined);
  const keyByName = new Map<string, string>();
  const all: typeof lock.packages = [];
  for (const [section, dev] of [['packages', false], ['packages-dev', true]] as const) {
    if (dev && !includeDev) continue;
    for (const p of lock[section] ?? []) {
      const node = b.add(p.name.toLowerCase(), p.version.replace(/^v/, ''), {
        dev,
        resolved: p.dist?.url,
        integrity: p.dist?.shasum || undefined,
        source: p.dist?.url ? 'registry' : p.source?.type === 'git' ? 'git' : 'unknown',
      });
      keyByName.set(p.name.toLowerCase(), node.key);
      all.push(p);
    }
  }
  for (const p of all) {
    const from = keyByName.get(p.name.toLowerCase())!;
    for (const n of Object.keys(p.require ?? {})) {
      const to = keyByName.get(n.toLowerCase());
      if (to) b.edge(from, to);
    }
  }
  if (composerJsonText) {
    try {
      const cj = JSON.parse(composerJsonText) as { require?: Record<string, string>; 'require-dev'?: Record<string, string> };
      for (const n of Object.keys({ ...cj.require, ...(includeDev ? cj['require-dev'] : {}) })) {
        const k = keyByName.get(n.toLowerCase());
        if (k) b.root(k);
      }
    } catch {
      /* ignore */
    }
  }
  return b.build();
}

/** NuGet packages.lock.json */
export function parseNugetLock(file: string, text: string): DependencyGraph {
  const lock = JSON.parse(text) as { dependencies?: Record<string, Record<string, { type?: string; resolved?: string; dependencies?: Record<string, string>; contentHash?: string }>> };
  const b = new GraphBuilder('NuGet', file);
  const keyByName = new Map<string, string>();
  const entries: [string, { type?: string; resolved?: string; dependencies?: Record<string, string> }][] = [];
  for (const fw of Object.values(lock.dependencies ?? {})) {
    for (const [name, e] of Object.entries(fw)) {
      if (e.type === 'Project' || !e.resolved) continue;
      const node = b.add(name, e.resolved, { integrity: (e as { contentHash?: string }).contentHash, source: 'registry' });
      keyByName.set(name.toLowerCase(), node.key);
      if (e.type === 'Direct' || e.type === 'CentralTransitive') b.root(node.key);
      entries.push([node.key, e]);
    }
  }
  for (const [from, e] of entries) {
    for (const n of Object.keys(e.dependencies ?? {})) {
      const to = keyByName.get(n.toLowerCase());
      if (to) b.edge(from, to);
    }
  }
  return b.build();
}

/** *.csproj / Directory.Packages.props – direct PackageReferences only. */
export function parseCsproj(file: string, text: string): DependencyGraph {
  const b = new GraphBuilder('NuGet', file, file);
  const re = /<Package(?:Reference|Version)\s+(?:Include|Update)="([^"]+)"(?:\s+Version="([^"]+)")?[^>]*?(?:\/>|>([\s\S]*?)<\/Package(?:Reference|Version)>)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const version = m[2] ?? /<Version>([^<]+)<\/Version>/.exec(m[3] ?? '')?.[1];
    if (!version || /[\[\(*$]/.test(version)) continue;
    b.root(b.add(m[1], version, { source: 'registry' }).key);
  }
  b.warnings.push('No packages.lock.json found – only direct NuGet references are checked. Enable <RestorePackagesWithLockFile> for transitive coverage.');
  return b.build();
}
