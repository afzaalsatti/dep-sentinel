/**
 * DepSentinel CLI – the same engine as the VS Code extension, for CI pipelines and pre-commit hooks.
 *
 *   dep-sentinel [path] [--fail-on <severity|none>] [--sarif <file>] [--json <file|->] [--no-dev] [--no-supply-chain]
 *
 * Exit codes: 0 = nothing at/above the --fail-on level, 1 = findings at/above it, 2 = scan error.
 */
import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { FileCache } from './core/cache';
import { Http } from './core/http';
import { isManifestFile, selectScanTargets } from './core/parsers';
import { Scanner } from './core/scanner';
import { readTextFile } from './core/fsutil';
import { describeFixText } from './core/versions';
import { findingSeverity, toMarkdown, toSarif, TOOL_VERSION } from './core/exporters';
import { CoreConfig, CoreContext, FileResult, SEVERITY_RANK, Severity } from './core/types';

const VERSION = TOOL_VERSION;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'target', 'out', 'vendor', '.venv', 'venv', 'bower_components', '.vscode-test', '.gradle', '.idea']);

interface Options {
  root: string;
  failOn: Severity | 'none';
  sarif?: string;
  json?: string;
  markdown?: string;
  includeDev: boolean;
  supplyChain: boolean;
  minimumSeverity: Severity;
  ignore: string[];
  exclude: string[];
  trust: string[];
  quiet: boolean;
}

const HELP = `DepSentinel ${VERSION} – dependency CVE & supply-chain scanner

Usage: dep-sentinel [path] [options]

Options:
  --fail-on <level>     Exit 1 if a finding is at/above: low | medium | high | critical | none   (default: high)
  --sarif <file>        Write a SARIF 2.1.0 report (GitHub code scanning, Azure DevOps, …)
  --json <file|->       Write the full results as JSON ("-" for stdout)
  --markdown <file>     Write a Markdown report (for PR comments, tickets, chat)
  --min-severity <lvl>  Hide vulnerabilities below this level (default: low)
  --ignore <ids>        Comma-separated advisory ids to ignore (GHSA-…, CVE-…)
  --exclude <dirs>      Comma-separated directories (relative to path) to skip
  --trust <pkgs>        Comma-separated name@version reviewed as safe (suppresses supply-chain signals only)
  --no-dev              Skip dev/test dependencies
  --no-supply-chain     Disable supply-chain heuristics
  -q, --quiet           Only print the summary
  -h, --help            Show this help
  -v, --version         Show the version

Suspicious packages count as "high", malicious ones as "critical" for --fail-on.`;

function parseArgs(argv: string[]): Options {
  const o: Options = { root: process.cwd(), failOn: 'high', includeDev: true, supplyChain: true, minimumSeverity: 'low', ignore: [], exclude: [], trust: [], quiet: false };
  const levels = ['low', 'medium', 'high', 'critical'];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`Missing value for ${a}`);
      return v;
    };
    switch (a) {
      case '-h':
      case '--help':
        console.log(HELP);
        process.exit(0);
      case '-v':
      case '--version':
        console.log(VERSION);
        process.exit(0);
      case '--fail-on': {
        const v = next();
        if (![...levels, 'none'].includes(v)) throw new Error(`Invalid --fail-on: ${v}`);
        o.failOn = v as Options['failOn'];
        break;
      }
      case '--min-severity': {
        const v = next();
        if (!levels.includes(v)) throw new Error(`Invalid --min-severity: ${v}`);
        o.minimumSeverity = v as Severity;
        break;
      }
      case '--sarif':
        o.sarif = next();
        break;
      case '--json':
        o.json = next();
        break;
      case '--markdown':
      case '--md':
        o.markdown = next();
        break;
      case '--ignore':
        o.ignore.push(...next().split(',').map((s) => s.trim()).filter(Boolean));
        break;
      case '--trust':
        o.trust.push(...next().split(',').map((s) => s.trim()).filter(Boolean));
        break;
      case '--exclude':
        o.exclude.push(...next().split(',').map((s) => s.trim()).filter(Boolean));
        break;
      case '--no-dev':
        o.includeDev = false;
        break;
      case '--no-supply-chain':
        o.supplyChain = false;
        break;
      case '-q':
      case '--quiet':
        o.quiet = true;
        break;
      default:
        if (a.startsWith('-')) throw new Error(`Unknown option ${a}`);
        o.root = path.resolve(a);
    }
  }
  return o;
}

/** Recursively collect manifests. Symlinks are never followed (Dirent reports them as neither file nor directory). */
async function walk(dir: string, exclude: Set<string>, out: string[] = []): Promise<string[]> {
  let entries: import('fs').Dirent[];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.') && !exclude.has(path.resolve(full))) await walk(full, exclude, out);
    } else if (e.isFile() && isManifestFile(e.name)) {
      out.push(path.join(dir, e.name));
    }
  }
  return out;
}

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const sevColor: Record<Severity, string> = { critical: '1;31', high: '31', medium: '33', unknown: '33', low: '36' };

function printHuman(results: FileResult[], root: string, quiet: boolean) {
  for (const r of results) {
    const rel = path.relative(root, r.file) || r.file;
    if (r.error) {
      console.log(`${c('31', '✘')} ${rel}: ${r.error}`);
      continue;
    }
    if (!r.findings.length) {
      if (!quiet) console.log(`${c('32', '✔')} ${rel} ${c('2', `(${r.packageCount} packages)`)}`);
      continue;
    }
    console.log(`\n${c('1', rel)} ${c('2', `(${r.ecosystem}, ${r.packageCount} packages)`)}`);
    if (quiet) continue;
    for (const f of r.findings) {
      const sev = findingSeverity(f);
      const tag = f.vulns.some((v) => v.isMalicious) ? 'MALICIOUS' : sev.toUpperCase();
      const origin = f.direct ? 'direct' : f.via.length ? `via ${f.via.join(' › ')}` : 'transitive';
      console.log(`  ${c(sevColor[sev], tag.padEnd(9))} ${f.name}@${f.version} ${c('2', origin)}${f.suspicious ? c('33', ' ⚠ suspicious') : ''}`);
      for (const v of f.vulns.slice(0, 5)) {
        const cve = v.aliases.find((x) => x.startsWith('CVE-'));
        console.log(`            ${v.id}${cve ? ` (${cve})` : ''} ${v.summary.slice(0, 100)}`);
      }
      if (f.vulns.length > 5) console.log(c('2', `            … ${f.vulns.length - 5} more`));
      const fix = describeFixText(f);
      if (fix) console.log(c(f.vulns.some((v) => v.isMalicious) ? '1;31' : '32', `            fix: ${fix}`));
      for (const s of f.signals.filter((x) => x.score >= 3)) console.log(c('33', `            [${s.code}] ${s.message.slice(0, 140)}`));
    }
  }
}

async function main() {
  let opts: Options;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(`${(e as Error).message}\n\n${HELP}`);
    process.exit(2);
  }
  const log = (m: string) => process.stderr.write(c('2', `${m}\n`));
  const exclude = new Set(opts.exclude.map((d) => path.resolve(opts.root, d)));
  const files = selectScanTargets(await walk(opts.root, exclude));
  if (!files.length) {
    console.log('No supported manifests or lockfiles found.');
    return;
  }
  const config: CoreConfig = {
    includeDev: opts.includeDev,
    resolveTransitive: true,
    maxDepth: 8,
    mavenRepos: ['https://repo1.maven.org/maven2'],
    npmRegistry: 'https://registry.npmjs.org',
    ignoredAdvisories: opts.ignore,
    minimumSeverity: opts.minimumSeverity,
    supplyChain: {
      enabled: opts.supplyChain,
      recentPublishHours: 72,
      threshold: 5,
      allowedRegistries: ['registry.npmjs.org', 'registry.yarnpkg.com', 'npm.pkg.github.com', 'repo1.maven.org', 'repo.maven.apache.org', 'pypi.org', 'files.pythonhosted.org', 'crates.io', 'index.crates.io', 'github.com/rust-lang/crates.io-index', 'rubygems.org', 'api.nuget.org', 'repo.packagist.org'],
      trustedPackages: opts.trust,
      maxRegistryLookups: 4000,
    },
  };
  const cache = new FileCache(path.join(process.env.DEP_SENTINEL_CACHE ?? path.join(os.homedir(), '.cache', 'dep-sentinel')));
  await cache.load(['pom', 'osv-vuln', 'release-facts', 'npm-version-v2', 'npm-abbrev', 'versions']);
  const ctx: CoreContext = {
    config,
    cache,
    http: new Http(),
    log: { info: () => undefined, warn: (m) => process.env.DEBUG && log(m), error: (m) => log(m) },
    readFile: (p) => readTextFile(p, (m) => log(m)),
    allowedRoots: [opts.root],
  };

  let results: FileResult[];
  try {
    results = await new Scanner(ctx).scan(files, opts.quiet ? undefined : log);
  } catch (e) {
    console.error(`Scan failed: ${(e as Error).message}`);
    process.exit(2);
  }

  if (opts.json === '-') console.log(JSON.stringify(results, null, 2));
  else {
    printHuman(results, opts.root, opts.quiet);
    if (opts.json) await fs.writeFile(opts.json, JSON.stringify(results, null, 2));
  }
  if (opts.sarif) await fs.writeFile(opts.sarif, JSON.stringify(await toSarif(results, opts.root), null, 2));
  if (opts.markdown) await fs.writeFile(opts.markdown, toMarkdown(results, opts.root));

  const findings = results.flatMap((r) => r.findings);
  const vulns = findings.reduce((n, f) => n + f.vulns.length, 0);
  const sus = findings.filter((f) => f.suspicious).length;
  const failing = opts.failOn === 'none' ? [] : findings.filter((f) => SEVERITY_RANK[findingSeverity(f)] >= SEVERITY_RANK[opts.failOn as Severity] && (f.vulns.length || f.suspicious));
  const packages = results.reduce((n, r) => n + r.packageCount, 0);
  if (opts.json !== '-') {
    console.log(`\n${files.length} manifest(s), ${packages} packages · ${vulns} vulnerabilities in ${findings.filter((f) => f.vulns.length).length} packages · ${sus} suspicious`);
    if (opts.failOn !== 'none') console.log(failing.length ? c('31', `✘ ${failing.length} package(s) at or above "${opts.failOn}"`) : c('32', `✔ nothing at or above "${opts.failOn}"`));
  }
  if (results.some((r) => r.error)) process.exitCode = 2;
  else if (failing.length) process.exitCode = 1;
}

if (require.main === module) void main();
