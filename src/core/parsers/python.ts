import * as path from 'path';
import { GraphBuilder } from '../graph';
import { parseToml, TomlTable, TomlValue } from '../toml';
import type { DependencyGraph } from '../types';

/** PEP 503 name normalisation. */
export function normalizePyName(n: string): string {
  return n.toLowerCase().replace(/[-_.]+/g, '-');
}

/** requirements.txt (supports pip-compile "# via" annotations to rebuild the tree). */
export function parseRequirements(file: string, text: string): DependencyGraph {
  const b = new GraphBuilder('PyPI', file, file);
  const lines = text.split(/\r?\n/);
  const viaOf = new Map<string, string[]>(); // child key -> parent names
  const keyByName = new Map<string, string>();
  let lastKey: string | undefined;
  let inVia = false;
  const unpinned: string[] = [];

  for (let raw of lines) {
    const viaMatch = /^\s+#\s+via\s*(.*)$/.exec(raw);
    if (viaMatch && lastKey) {
      inVia = true;
      const first = viaMatch[1].trim();
      if (first) viaOf.set(lastKey, [...(viaOf.get(lastKey) ?? []), first]);
      continue;
    }
    const contMatch = /^\s+#\s+(\S.*)$/.exec(raw);
    if (inVia && contMatch && lastKey) {
      viaOf.set(lastKey, [...(viaOf.get(lastKey) ?? []), contMatch[1].trim()]);
      continue;
    }
    inVia = false;
    raw = raw.replace(/\s+#.*$/, '').replace(/\\$/, '').trim();
    if (!raw || raw.startsWith('#') || raw.startsWith('--hash')) continue;
    if (raw.startsWith('-')) {
      if (/^-(r|c)\s|^--(requirement|constraint)/.test(raw)) b.warnings.push(`Nested requirement file not followed: ${raw}`);
      continue;
    }
    if (/^(git\+|https?:|file:|\.)/.test(raw) || raw.includes(' @ ')) {
      const name = raw.includes(' @ ') ? raw.split(' @ ')[0].trim() : raw;
      const node = b.add(normalizePyName(name.replace(/\[.*\]/, '')), 'unknown', { source: /git\+/.test(raw) ? 'git' : 'url' });
      b.root(node.key);
      lastKey = node.key;
      continue;
    }
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(===?|~=|>=|<=|>|<|!=)?\s*([^;\s,]*)/.exec(raw);
    if (!m) continue;
    const name = normalizePyName(m[1]);
    if (m[3] !== '==' && m[3] !== '===') {
      unpinned.push(name);
      lastKey = undefined;
      continue;
    }
    const node = b.add(name, m[4], { source: 'registry' });
    keyByName.set(name, node.key);
    lastKey = node.key;
  }

  if (unpinned.length) {
    b.warnings.push(`Unpinned requirements cannot be checked precisely: ${unpinned.slice(0, 10).join(', ')}${unpinned.length > 10 ? '…' : ''}. Pin versions (pip-compile / pip freeze) for accurate results.`);
  }

  let hasVia = false;
  for (const [child, parents] of viaOf) {
    for (const p of parents) {
      if (p.startsWith('-r ') || p.startsWith('-c ')) {
        b.root(child);
        continue;
      }
      const pk = keyByName.get(normalizePyName(p));
      if (pk) {
        b.edge(pk, child);
        hasVia = true;
      }
    }
  }
  if (!hasVia) for (const k of keyByName.values()) b.root(k);
  return b.build();
}

/** Pipfile.lock (flat; direct deps come from Pipfile when present). */
export function parsePipfileLock(file: string, text: string, pipfileText: string | undefined, includeDev: boolean): DependencyGraph {
  const lock = JSON.parse(text) as Record<string, Record<string, { version?: string; git?: string }>>;
  const pipfile = path.join(path.dirname(file), 'Pipfile');
  const b = new GraphBuilder('PyPI', file, pipfileText ? pipfile : undefined);
  const direct = new Set<string>();
  if (pipfileText) {
    try {
      const t = parseToml(pipfileText);
      for (const sec of ['packages', ...(includeDev ? ['dev-packages'] : [])]) {
        Object.keys((t[sec] as TomlTable) ?? {}).forEach((n) => direct.add(normalizePyName(n)));
      }
    } catch {
      /* ignore */
    }
  }
  for (const [section, dev] of [['default', false], ['develop', true]] as const) {
    if (dev && !includeDev) continue;
    for (const [n, e] of Object.entries(lock[section] ?? {})) {
      const name = normalizePyName(n);
      const version = e.version?.replace(/^==/, '') ?? 'unknown';
      const node = b.add(name, version, { dev, source: e.git ? 'git' : 'registry' });
      if (direct.size === 0 || direct.has(name)) b.root(node.key);
    }
  }
  return b.build();
}

/** Extract dependency names from pyproject.toml (PEP 621 + Poetry). */
export function pyprojectDirectNames(text: string | undefined, includeDev: boolean): Set<string> {
  const out = new Set<string>();
  if (!text) return out;
  try {
    const t = parseToml(text);
    const project = t.project as TomlTable | undefined;
    for (const d of (project?.dependencies as string[] | undefined) ?? []) {
      const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(d);
      if (m) out.add(normalizePyName(m[1]));
    }
    if (includeDev) {
      const groups = (t['dependency-groups'] as TomlTable | undefined) ?? {};
      const optional = (project?.['optional-dependencies'] as TomlTable | undefined) ?? {};
      for (const list of [...Object.values(groups), ...Object.values(optional)]) {
        for (const d of (list as TomlValue[]) ?? []) {
          const m = typeof d === 'string' ? /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(d) : null;
          if (m) out.add(normalizePyName(m[1]));
        }
      }
    }
    const poetry = (t.tool as TomlTable | undefined)?.poetry as TomlTable | undefined;
    if (poetry) {
      Object.keys((poetry.dependencies as TomlTable) ?? {}).forEach((n) => n !== 'python' && out.add(normalizePyName(n)));
      if (includeDev) {
        Object.keys((poetry['dev-dependencies'] as TomlTable) ?? {}).forEach((n) => out.add(normalizePyName(n)));
        for (const g of Object.values((poetry.group as TomlTable) ?? {})) {
          Object.keys(((g as TomlTable).dependencies as TomlTable) ?? {}).forEach((n) => out.add(normalizePyName(n)));
        }
      }
    }
  } catch {
    /* ignore */
  }
  return out;
}

/** poetry.lock and uv.lock share the [[package]] layout. */
export function parsePoetryOrUvLock(file: string, text: string, pyprojectText: string | undefined, includeDev: boolean): DependencyGraph {
  const t = parseToml(text);
  const pyproject = path.join(path.dirname(file), 'pyproject.toml');
  const b = new GraphBuilder('PyPI', file, pyprojectText ? pyproject : undefined);
  const pkgs = (t.package as TomlTable[] | undefined) ?? [];
  const keyByName = new Map<string, string>();
  const projectRoots: TomlTable[] = [];

  for (const p of pkgs) {
    const name = normalizePyName(String(p.name));
    const version = String(p.version ?? 'unknown');
    const source = p.source as TomlTable | undefined;
    if (source && (source.editable !== undefined || source.virtual !== undefined)) {
      projectRoots.push(p);
      continue;
    }
    const dev = p.category === 'dev';
    const node = b.add(name, version, {
      dev,
      source: source?.git ? 'git' : source?.url || source?.path ? 'url' : 'registry',
      resolved: typeof source?.registry === 'string' ? source.registry : typeof source?.url === 'string' ? source.url : undefined,
    });
    keyByName.set(name, node.key);
  }

  const depNames = (p: TomlTable): string[] => {
    const deps = p.dependencies;
    if (Array.isArray(deps)) return deps.map((d) => normalizePyName(String((d as TomlTable).name ?? d)));
    if (deps && typeof deps === 'object') return Object.keys(deps).map(normalizePyName);
    return [];
  };

  for (const p of pkgs) {
    const from = keyByName.get(normalizePyName(String(p.name)));
    if (!from) continue;
    for (const d of depNames(p)) {
      const to = keyByName.get(d);
      if (to) b.edge(from, to);
    }
  }

  const direct = pyprojectDirectNames(pyprojectText, includeDev);
  for (const rp of projectRoots) {
    depNames(rp).forEach((d) => direct.add(d));
    if (includeDev) {
      for (const list of Object.values((rp['dev-dependencies'] as TomlTable) ?? {})) {
        for (const d of (list as TomlTable[]) ?? []) direct.add(normalizePyName(String(d.name)));
      }
    }
  }
  for (const n of direct) {
    const k = keyByName.get(n);
    if (k) b.root(k);
  }
  if (!includeDev) for (const [k, n] of b.nodes) if (n.dev) b.nodes.delete(k);
  return b.build();
}
