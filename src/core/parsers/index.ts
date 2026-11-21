import * as path from 'path';
import YAML from 'yaml';
import { MavenResolver } from '../resolvers/maven';
import { resolvePackageJson } from '../resolvers/npm';
import type { CoreContext, DependencyGraph } from '../types';
import { parseGradleLockfile, resolveGradleBuild, resolveVersionCatalog } from './gradle';
import { parseCargoLock, parseComposerLock, parseCsproj, parseGemfileLock, parseGoMod, parseNugetLock } from './misc';
import { parsePackageLock } from './npm';
import { parsePnpmLock } from './pnpm';
import { parsePipfileLock, parsePoetryOrUvLock, parseRequirements } from './python';
import { parseYarnLock } from './yarn';

/** Parse (and, if needed, resolve) one manifest/lockfile into a dependency graph. */
export async function buildGraph(file: string, ctx: CoreContext): Promise<DependencyGraph> {
  const text = await ctx.readFile(file);
  if (text === undefined) throw new Error(`Cannot read ${file}`);
  const dir = path.dirname(file);
  const base = path.basename(file).toLowerCase();
  const sibling = (n: string) => ctx.readFile(path.join(dir, n));
  const dev = ctx.config.includeDev;

  switch (base) {
    case 'package-lock.json':
    case 'npm-shrinkwrap.json':
      return parsePackageLock(file, text, await sibling('package.json'), dev);
    case 'yarn.lock':
      return parseYarnLock(file, text, await sibling('package.json'), dev);
    case 'pnpm-lock.yaml':
      return parsePnpmLock(file, text, dev);
    case 'package.json':
      return resolvePackageJson(file, text, ctx);
    case 'pom.xml':
      return new MavenResolver(ctx).resolvePomFile(file, text, dev, ctx.config.resolveTransitive ? ctx.config.maxDepth : 1);
    case 'build.gradle':
    case 'build.gradle.kts':
      return resolveGradleBuild(file, text, ctx);
    case 'libs.versions.toml':
      return resolveVersionCatalog(file, text, ctx);
    case 'gradle.lockfile': {
      const groovy = await sibling('build.gradle');
      const kts = groovy === undefined ? await sibling('build.gradle.kts') : undefined;
      const buildFile = path.join(dir, groovy !== undefined ? 'build.gradle' : 'build.gradle.kts');
      return parseGradleLockfile(file, text, buildFile, groovy ?? kts, dev);
    }
    case 'poetry.lock':
    case 'uv.lock':
      return parsePoetryOrUvLock(file, text, await sibling('pyproject.toml'), dev);
    case 'pipfile.lock':
      return parsePipfileLock(file, text, await sibling('Pipfile'), dev);
    case 'go.mod':
      return parseGoMod(file, text);
    case 'cargo.lock':
      return parseCargoLock(file, text);
    case 'gemfile.lock':
      return parseGemfileLock(file, text);
    case 'composer.lock':
      return parseComposerLock(file, text, await sibling('composer.json'), dev);
    case 'packages.lock.json':
      return parseNugetLock(file, text);
  }
  if (/requirements.*\.txt$/.test(base) || base.endsWith('.requirements.txt')) return parseRequirements(file, text);
  if (base.endsWith('.csproj') || base.endsWith('.fsproj') || base.endsWith('.vbproj') || base === 'directory.packages.props') return parseCsproj(file, text);
  throw new Error(`Unsupported file ${file}`);
}

/** Glob of every file name DepSentinel understands. */
export const MANIFEST_GLOB =
  '**/{package.json,package-lock.json,npm-shrinkwrap.json,yarn.lock,pnpm-lock.yaml,pom.xml,build.gradle,build.gradle.kts,gradle.lockfile,libs.versions.toml,requirements*.txt,Pipfile.lock,poetry.lock,uv.lock,go.mod,Cargo.lock,Gemfile.lock,composer.lock,packages.lock.json,*.csproj,*.fsproj,Directory.Packages.props}';

/** Same set of files as MANIFEST_GLOB, for callers that walk the file system themselves (CLI). */
export function isManifestFile(basename: string): boolean {
  return (
    /^(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|pom\.xml|build\.gradle|build\.gradle\.kts|gradle\.lockfile|libs\.versions\.toml|Pipfile\.lock|poetry\.lock|uv\.lock|go\.mod|Cargo\.lock|Gemfile\.lock|composer\.lock|packages\.lock\.json|Directory\.Packages\.props)$/.test(basename) ||
    /^requirements.*\.txt$/.test(basename) ||
    /\.(cs|fs)proj$/.test(basename)
  );
}

/** Does the npm/yarn/pnpm lockfile in `lockDir` cover the package in `dir` (i.e. is `dir` a declared workspace)? */
export type WorkspaceCoverage = (lockDir: string, dir: string) => boolean;

const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

/** Convert a workspace glob ("packages/*", "apps/**") to a RegExp over a "/"-separated relative path. */
function workspaceGlob(pattern: string): RegExp {
  const p = pattern.trim().replace(/^\.\//, '').replace(/\/+$/, '');
  const re = p
    .split(/(\*\*\/?|\*|\?)/)
    .map((part) => (part.startsWith('**') ? '(?:.*/)?' + (part.endsWith('/') ? '' : '.*') : part === '*' ? '[^/]*' : part === '?' ? '[^/]' : part.replace(/[.+^${}()|[\]\\]/g, '\\$&')))
    .join('');
  return new RegExp(`^${re}$`);
}

/** Workspace member globs declared next to a lockfile (package.json "workspaces" or pnpm-workspace.yaml). */
async function declaredWorkspaces(dir: string, readFile: (p: string) => Promise<string | undefined>): Promise<string[]> {
  const out: string[] = [];
  const pkg = await readFile(path.join(dir, 'package.json'));
  if (pkg) {
    try {
      const ws = JSON.parse(pkg).workspaces;
      const list = Array.isArray(ws) ? ws : Array.isArray(ws?.packages) ? ws.packages : [];
      out.push(...list.filter((x: unknown): x is string => typeof x === 'string'));
    } catch {
      /* unparsable package.json: no workspaces */
    }
  }
  const pnpm = await readFile(path.join(dir, 'pnpm-workspace.yaml'));
  if (pnpm) {
    try {
      const list = YAML.parse(pnpm)?.packages;
      if (Array.isArray(list)) out.push(...list.filter((x: unknown): x is string => typeof x === 'string'));
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Build a WorkspaceCoverage from the workspace declarations next to each lockfile, so an unrelated project that just
 * happens to live below another project's lockfile (e.g. a React app inside a folder that also has tooling) is still scanned.
 */
export async function workspaceCoverage(files: string[], readFile: (p: string) => Promise<string | undefined>): Promise<WorkspaceCoverage> {
  const lockDirs = [...new Set(files.filter((f) => NPM_LOCKS.includes(path.basename(f))).map((f) => path.dirname(f)))];
  const globs = new Map<string, { include: RegExp[]; exclude: RegExp[] }>();
  await Promise.all(
    lockDirs.map(async (d) => {
      const pats = await declaredWorkspaces(d, readFile);
      globs.set(d, {
        include: pats.filter((p) => !p.startsWith('!')).map(workspaceGlob),
        exclude: pats.filter((p) => p.startsWith('!')).map((p) => workspaceGlob(p.slice(1))),
      });
    }),
  );
  return (lockDir, dir) => {
    const g = globs.get(lockDir);
    if (!g) return false;
    const rel = path.relative(lockDir, dir).split(path.sep).join('/');
    return g.include.some((r) => r.test(rel)) && !g.exclude.some((r) => r.test(rel));
  };
}

/** selectScanTargets, after reading workspace declarations so only real workspace members are folded into a parent lockfile. */
export async function discoverScanTargets(files: string[], readFile: (p: string) => Promise<string | undefined>): Promise<string[]> {
  return selectScanTargets(files, await workspaceCoverage(files, readFile));
}

/**
 * Choose which files to scan: per directory and ecosystem, prefer the most precise source
 * (lockfile over manifest), and skip package.json files covered by an ancestor lockfile (workspaces).
 * Without `covers`, any package.json below a lockfile is assumed to be a workspace of it.
 */
export function selectScanTargets(files: string[], covers: WorkspaceCoverage = () => true): string[] {
  const byDir = new Map<string, Set<string>>();
  for (const f of files) {
    const d = path.dirname(f);
    if (!byDir.has(d)) byDir.set(d, new Set());
    byDir.get(d)!.add(path.basename(f));
  }
  const has = (d: string, n: string) => byDir.get(d)?.has(n) ?? false;
  const npmLocks = NPM_LOCKS;
  const lockDirs = [...byDir.keys()].filter((d) => npmLocks.some((l) => has(d, l)));
  const coveredByAncestorLock = (d: string) => lockDirs.some((ld) => ld !== d && (d + path.sep).startsWith(ld + path.sep) && covers(ld, d));

  const out: string[] = [];
  for (const [dir, names] of byDir) {
    const add = (n: string) => out.push(path.join(dir, n));
    // npm family
    const lock = npmLocks.find((l) => names.has(l));
    if (lock) add(lock);
    else if (names.has('package.json') && !coveredByAncestorLock(dir) && !dir.split(/[\\/]/).includes('node_modules')) add('package.json');
    // Maven / Gradle
    if (names.has('pom.xml')) add('pom.xml');
    if (names.has('gradle.lockfile')) add('gradle.lockfile');
    else {
      if (names.has('build.gradle')) add('build.gradle');
      if (names.has('build.gradle.kts')) add('build.gradle.kts');
    }
    if (names.has('libs.versions.toml') && !names.has('gradle.lockfile')) add('libs.versions.toml');
    // Python
    const pyLock = ['poetry.lock', 'uv.lock', 'Pipfile.lock'].find((l) => names.has(l));
    if (pyLock) add(pyLock);
    else for (const n of names) if (/^requirements.*\.txt$/i.test(n)) add(n);
    // Others
    for (const n of ['go.mod', 'Cargo.lock', 'Gemfile.lock', 'composer.lock']) if (names.has(n)) add(n);
    if (names.has('packages.lock.json')) add('packages.lock.json');
    else for (const n of names) if (/\.(cs|fs|vb)proj$/i.test(n) || n === 'Directory.Packages.props') add(n);
  }
  return out.sort();
}
