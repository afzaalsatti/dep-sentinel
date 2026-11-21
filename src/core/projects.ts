import * as path from 'path';
import type { Ecosystem, FileResult, PackageFinding, Severity } from './types';

/** A project inside the workspace: one or more scanned files of the same ecosystem under a common root folder. */
export interface Project {
  /** Stable id, safe for HTML anchors. */
  id: string;
  /** Display name: folder path relative to its workspace folder, or the workspace folder's name for the root. */
  name: string;
  root: string;
  ecosystem: Ecosystem;
  results: FileResult[];
}

export const ECOSYSTEM_LABEL: Record<Ecosystem, string> = {
  npm: 'JavaScript / TypeScript (npm)',
  Maven: 'Java / Kotlin (Maven, Gradle)',
  PyPI: 'Python',
  Go: 'Go',
  'crates.io': 'Rust',
  RubyGems: 'Ruby',
  Packagist: 'PHP',
  NuGet: '.NET',
};

const isUnder = (dir: string, root: string) => dir === root || dir.startsWith(root.endsWith(path.sep) ? root : root + path.sep);

/**
 * Group scan results into projects. A file joins the project of its shallowest ancestor folder that has a scanned file of the
 * same ecosystem (Maven modules join their parent POM, Gradle sub-projects their root build), so a React app and a Java service
 * opened side by side, or nested, show up as separate projects.
 * `roots` are the workspace folders; names are relative to the one that contains the project.
 */
export function groupProjects(results: FileResult[], roots: { name: string; path: string }[]): Project[] {
  const dirs = new Map<Ecosystem, string[]>();
  for (const r of results) {
    const list = dirs.get(r.ecosystem) ?? [];
    list.push(path.dirname(r.file));
    dirs.set(r.ecosystem, list);
  }
  const byRoot = new Map<string, Project>();
  for (const r of results) {
    const dir = path.dirname(r.file);
    const candidates = (dirs.get(r.ecosystem) ?? []).filter((d) => isUnder(dir, d));
    const projRoot = candidates.reduce((best, d) => (d.length < best.length ? d : best), dir);
    const key = `${r.ecosystem}|${projRoot}`;
    let p = byRoot.get(key);
    if (!p) {
      p = { id: '', name: projectName(projRoot, roots), root: projRoot, ecosystem: r.ecosystem, results: [] };
      byRoot.set(key, p);
    }
    p.results.push(r);
  }
  const projects = [...byRoot.values()];
  // Same folder, several ecosystems (e.g. pom.xml + package.json side by side): disambiguate with the ecosystem.
  const nameCount = new Map<string, number>();
  for (const p of projects) nameCount.set(p.name, (nameCount.get(p.name) ?? 0) + 1);
  for (const p of projects) if (nameCount.get(p.name)! > 1) p.name = `${p.name} (${p.ecosystem})`;
  projects.sort((a, b) => projectRank(b) - projectRank(a) || a.name.localeCompare(b.name));
  projects.forEach((p, i) => (p.id = `project-${i + 1}`));
  for (const p of projects) p.results.sort((a, b) => a.file.localeCompare(b.file));
  return projects;
}

function projectName(dir: string, roots: { name: string; path: string }[]): string {
  const root = roots.filter((r) => isUnder(dir, r.path)).sort((a, b) => b.path.length - a.path.length)[0];
  if (!root) return path.basename(dir) || dir;
  const rel = path.relative(root.path, dir).split(path.sep).join('/');
  const prefix = roots.length > 1 ? `${root.name}/` : '';
  return rel ? `${prefix}${rel}` : root.name;
}

export interface ProjectStats {
  packages: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  suspicious: number;
  malicious: number;
  vulns: number;
  affected: number;
}

export function statsOf(results: FileResult[]): ProjectStats {
  const findings: PackageFinding[] = results.flatMap((r) => r.findings);
  const vulns = findings.flatMap((f) => f.vulns);
  const count = (...s: Severity[]) => vulns.filter((v) => !v.isMalicious && s.includes(v.severity)).length;
  return {
    packages: results.reduce((n, r) => n + r.packageCount, 0),
    critical: count('critical'),
    high: count('high'),
    medium: count('medium', 'unknown'),
    low: count('low'),
    suspicious: findings.filter((f) => f.suspicious && !f.vulns.some((v) => v.isMalicious)).length,
    malicious: findings.filter((f) => f.vulns.some((v) => v.isMalicious)).length,
    vulns: vulns.length,
    affected: findings.filter((f) => f.vulns.length || f.suspicious).length,
  };
}

/** Sort key: projects with the worst problems first. */
function projectRank(p: Project): number {
  const s = statsOf(p.results);
  return s.malicious * 1e8 + s.critical * 1e6 + s.high * 1e4 + s.suspicious * 1e3 + s.medium * 10 + s.low;
}
