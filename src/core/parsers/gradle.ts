import * as path from 'path';
import { GraphBuilder } from '../graph';
import { MavenDep, MavenResolver, RootItem } from '../resolvers/maven';
import { parseToml, TomlTable, TomlValue } from '../toml';
import type { CoreContext, DependencyGraph } from '../types';

const PROD_CONFIGS = ['implementation', 'api', 'compile', 'runtimeOnly', 'runtime', 'compileOnly', 'kapt', 'ksp', 'annotationProcessor', 'classpath'];
const configRe = '([A-Za-z]*?(?:[Ii]mplementation|[Aa]pi|[Cc]ompile|[Rr]untimeOnly|[Rr]untime|[Cc]ompileOnly|kapt|ksp|[Aa]nnotationProcessor|classpath))';

export interface GradleDecl {
  groupId: string;
  artifactId: string;
  version?: string;
  dev: boolean;
  platform: boolean;
}

function readVars(text: string, props: Record<string, string>) {
  const vars: Record<string, string> = { ...props };
  const re = /(?:def|val|var|ext\.|set\(\s*["'])\s*([A-Za-z_][\w.]*)["']?\s*(?:=|,)\s*["']([^"'$]+)["']/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) vars[m[1]] = m[2];
  // ext { foo = '1.0' } blocks
  const extBlock = /ext\s*\{([\s\S]*?)\}/g;
  while ((m = extBlock.exec(text))) {
    const inner = /([A-Za-z_]\w*)\s*=\s*["']([^"']+)["']/g;
    let n: RegExpExecArray | null;
    while ((n = inner.exec(m[1]))) vars[n[1]] = n[2];
  }
  return vars;
}

function subst(v: string | undefined, vars: Record<string, string>): string | undefined {
  if (!v) return v;
  const out = v.replace(/\$\{?([A-Za-z_][\w.]*)\}?/g, (m, k: string) => vars[k] ?? vars[k.replace(/^project\./, '')] ?? m);
  return out.includes('$') ? undefined : out;
}

export function parseGradleBuild(text: string, props: Record<string, string> = {}): { decls: GradleDecl[]; bootVersion?: string } {
  const vars = readVars(text, props);
  const decls: GradleDecl[] = [];
  const isDev = (cfg: string) => /^test|^androidTest|Test(Implementation|Api|CompileOnly|RuntimeOnly|Compile|Runtime)$/.test(cfg) && !PROD_CONFIGS.includes(cfg);
  // implementation 'g:a:v' / implementation("g:a:v") / implementation(platform("g:a:v"))
  const strRe = new RegExp(`\\b${configRe}\\s*\\(?\\s*(platform|enforcedPlatform)?\\s*\\(?\\s*["']([^"':\\s]+):([^"':\\s]+)(?::([^"'@:\\s]+))?(?::[^"']*)?["']`, 'g');
  let m: RegExpExecArray | null;
  while ((m = strRe.exec(text))) {
    decls.push({ groupId: m[3], artifactId: m[4], version: subst(m[5], vars), dev: isDev(m[1]), platform: !!m[2] });
  }
  // implementation group: 'g', name: 'a', version: 'v'
  const mapRe = new RegExp(`\\b${configRe}\\s*\\(?\\s*group\\s*[:=]\\s*["']([^"']+)["']\\s*,\\s*name\\s*[:=]\\s*["']([^"']+)["'](?:\\s*,\\s*version\\s*[:=]\\s*["']([^"']+)["'])?`, 'g');
  while ((m = mapRe.exec(text))) {
    decls.push({ groupId: m[2], artifactId: m[3], version: subst(m[4], vars), dev: isDev(m[1]), platform: false });
  }
  const boot = /id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s*version\s*["']([^"']+)["']/.exec(text);
  return { decls, bootVersion: boot?.[1] };
}

function parseProps(text: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of (text ?? '').split(/\r?\n/)) {
    const m = /^\s*([\w.-]+)\s*[=:]\s*(.*?)\s*$/.exec(line);
    if (m && !line.trimStart().startsWith('#')) out[m[1]] = m[2];
  }
  return out;
}

export async function resolveGradleBuild(file: string, text: string, ctx: CoreContext): Promise<DependencyGraph> {
  const dir = path.dirname(file);
  const props = { ...parseProps(await ctx.readFile(path.join(dir, '..', 'gradle.properties'))), ...parseProps(await ctx.readFile(path.join(dir, 'gradle.properties'))) };
  const { decls, bootVersion } = parseGradleBuild(text, props);
  const resolver = new MavenResolver(ctx);
  const boms = decls.filter((d) => d.platform && d.version).map((d) => ({ groupId: d.groupId, artifactId: d.artifactId, version: d.version! }));
  if (bootVersion) boms.push({ groupId: 'org.springframework.boot', artifactId: 'spring-boot-dependencies', version: bootVersion });
  const managed = await resolver.bomManaged(boms);
  const roots: RootItem[] = decls
    .filter((d) => !d.platform && (ctx.config.includeDev || !d.dev))
    .map((d) => ({ dep: { groupId: d.groupId, artifactId: d.artifactId, version: d.version, exclusions: [] } as MavenDep, dev: d.dev }));
  const b = new GraphBuilder('Maven', file, file);
  if (/libs\.[\w.]+/.test(text)) b.warnings.push('Version-catalog references (libs.*) are scanned via gradle/libs.versions.toml.');
  if (!ctx.config.resolveTransitive) {
    for (const r of roots) {
      const v = r.dep.version ?? managed.get(`${r.dep.groupId}:${r.dep.artifactId}`)?.version;
      if (v) b.root(b.add(`${r.dep.groupId}:${r.dep.artifactId}`, v, { dev: r.dev, source: 'registry' }).key);
    }
    return b.build();
  }
  return resolver.resolve(file, roots, managed, ctx.config.maxDepth, b);
}

/** gradle/libs.versions.toml */
export async function resolveVersionCatalog(file: string, text: string, ctx: CoreContext): Promise<DependencyGraph> {
  const t = parseToml(text);
  const versions = (t.versions as TomlTable) ?? {};
  const verOf = (v: TomlValue | undefined): string | undefined => {
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      if (typeof v.ref === 'string') return verOf(versions[v.ref]);
      return (v.strictly ?? v.require ?? v.prefer) as string | undefined;
    }
    return undefined;
  };
  const roots: RootItem[] = [];
  for (const lib of Object.values((t.libraries as TomlTable) ?? {})) {
    let g: string | undefined, a: string | undefined, v: string | undefined;
    if (typeof lib === 'string') [g, a, v] = lib.split(':');
    else if (lib && typeof lib === 'object' && !Array.isArray(lib)) {
      if (typeof lib.module === 'string') [g, a] = lib.module.split(':');
      else [g, a] = [lib.group as string, lib.name as string];
      v = verOf(lib.version) ?? (typeof (lib as TomlTable)['version.ref'] === 'string' ? verOf(versions[(lib as TomlTable)['version.ref'] as string]) : undefined);
    }
    if (g && a && v) roots.push({ dep: { groupId: g, artifactId: a, version: v, exclusions: [] }, dev: /test|junit|mockito|assertj|mockk|kotest/i.test(`${g}:${a}`) });
  }
  const resolver = new MavenResolver(ctx);
  const filtered = roots.filter((r) => ctx.config.includeDev || !r.dev);
  return resolver.resolve(file, filtered, new Map(), ctx.config.resolveTransitive ? ctx.config.maxDepth : 1);
}

/** gradle.lockfile – complete resolved list (no edges). */
export function parseGradleLockfile(file: string, text: string, buildFile: string | undefined, buildText: string | undefined, includeDev: boolean): DependencyGraph {
  const b = new GraphBuilder('Maven', file, buildText ? buildFile : undefined);
  const direct = new Set(buildText ? parseGradleBuild(buildText).decls.map((d) => `${d.groupId}:${d.artifactId}`) : []);
  for (const line of text.split(/\r?\n/)) {
    const m = /^([^#:\s]+):([^:\s]+):([^=\s]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    const configs = m[4].split(',');
    const dev = configs.every((c) => /^test|Test/.test(c));
    if (dev && !includeDev) continue;
    const node = b.add(`${m[1]}:${m[2]}`, m[3], { dev, source: 'registry' });
    if (direct.size === 0 || direct.has(node.name)) b.root(node.key);
  }
  return b.build();
}
