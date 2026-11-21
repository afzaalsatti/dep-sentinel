import { computePaths, PathInfo } from './graph';
import { createLimiter } from './http';
import { osvKey, queryOsv } from './osv';
import { buildGraph } from './parsers';
import { SupplyChainAnalyzer, SupplyChainInput } from './supplyChain';
import { recommendFix } from './versions';
import { listPublishedVersions, versionSet } from './registryVersions';
import {
  CoreContext,
  DependencyGraph,
  FileResult,
  PackageFinding,
  SEVERITY_RANK,
  Severity,
  SupplyChainSignal,
  Vulnerability,
} from './types';

export type ProgressFn = (message: string) => void;

export class Scanner {
  constructor(private readonly ctx: CoreContext) {}

  async scan(files: string[], progress: ProgressFn = () => undefined): Promise<FileResult[]> {
    const { ctx } = this;
    const limit = createLimiter(3);
    let done = 0;
    progress(`Reading ${files.length} manifest(s)…`);
    const parsed = await Promise.all(
      files.map((file) =>
        limit(async () => {
          try {
            const graph = await buildGraph(file, ctx);
            progress(`Resolved ${++done}/${files.length}: ${graph.nodes.size} packages in ${shortName(file)}`);
            return { file, graph };
          } catch (e) {
            ctx.log.error(`Failed to parse ${file}: ${(e as Error).stack ?? e}`);
            return { file, error: (e as Error).message };
          }
        }),
      ),
    );

    // Collect unique packages across all files.
    const unique = new Map<string, SupplyChainInput>();
    const pathInfo = new Map<DependencyGraph, Map<string, PathInfo>>();
    for (const p of parsed) {
      if (!p.graph) continue;
      const paths = computePaths(p.graph);
      pathInfo.set(p.graph, paths);
      for (const node of p.graph.nodes.values()) {
        const k = osvKey({ ecosystem: p.graph.ecosystem, name: node.name, version: node.version });
        const direct = paths.get(node.key)?.direct ?? false;
        const existing = unique.get(k);
        if (!existing || (direct && !existing.direct)) unique.set(k, { ecosystem: p.graph.ecosystem, name: node.name, version: node.version, direct, node });
      }
    }

    if (ctx.isCancelled?.()) throw new Error('Scan cancelled');
    progress(`Checking ${unique.size} packages against OSV/CVE advisories…`);
    const vulns = await queryOsv([...unique.values()], ctx);

    let signals = new Map<string, SupplyChainSignal[]>();
    if (ctx.config.supplyChain.enabled) {
      progress(`Analyzing supply-chain risk for ${unique.size} packages…`);
      signals = await new SupplyChainAnalyzer(ctx).analyze([...unique.values()]);
    }
    // Published versions for vulnerable packages, so fix recommendations only name installable releases.
    const published = new Map<string, Set<string> | undefined>();
    const versionLimit = createLimiter(8);
    await Promise.all(
      [...unique].filter(([k]) => vulns.has(k)).map(([k, i]) =>
        versionLimit(async () => published.set(k, versionSet(await listPublishedVersions(ctx, i.ecosystem, i.name)))),
      ),
    );
    await ctx.cache.flush();

    const scannedAt = new Date().toISOString();
    return parsed.map((p): FileResult => {
      if (!p.graph) return { file: p.file, ecosystem: 'npm', packageCount: 0, findings: [], warnings: [], error: p.error, scannedAt };
      const findings = this.assemble(p.graph, pathInfo.get(p.graph)!, vulns, signals, published);
      return {
        file: p.file,
        manifestFile: p.graph.manifestFile,
        ecosystem: p.graph.ecosystem,
        packageCount: p.graph.nodes.size,
        findings,
        warnings: p.graph.warnings,
        scannedAt,
      };
    });
  }

  private assemble(
    graph: DependencyGraph,
    paths: Map<string, PathInfo>,
    vulnMap: Map<string, Vulnerability[]>,
    signalMap: Map<string, SupplyChainSignal[]>,
    published: Map<string, Set<string> | undefined>,
  ): PackageFinding[] {
    const cfg = this.ctx.config;
    const ignored = new Set(cfg.ignoredAdvisories.map((s) => s.toUpperCase()));
    const minRank = SEVERITY_RANK[cfg.minimumSeverity];
    const findings: PackageFinding[] = [];

    for (const node of graph.nodes.values()) {
      const k = osvKey({ ecosystem: graph.ecosystem, name: node.name, version: node.version });
      const vulns = (vulnMap.get(k) ?? []).filter(
        (v) => !ignored.has(v.id.toUpperCase()) && !v.aliases.some((a) => ignored.has(a.toUpperCase())) && (v.isMalicious || SEVERITY_RANK[v.severity] >= minRank),
      );
      const signals = [...(signalMap.get(k) ?? [])];
      const malicious = vulns.filter((v) => v.isMalicious);
      if (malicious.length) {
        signals.unshift({
          code: 'known-malicious',
          severity: 'critical',
          score: 100,
          message: `Reported as MALICIOUS (${malicious.map((m) => m.id).join(', ')}). Remove it immediately and rotate any credentials on machines where it was installed.`,
        });
      }
      const riskScore = signals.reduce((s, x) => s + x.score, 0);
      const suspicious = riskScore >= cfg.supplyChain.threshold;
      const notable = vulns.length > 0 || suspicious || signals.some((s) => s.score >= 3);
      if (!notable) continue;

      const info = paths.get(node.key) ?? { direct: false, via: [] };
      const sevs: Severity[] = [...vulns.map((v) => v.severity), ...signals.filter((s) => s.score >= 3 || suspicious).map((s) => s.severity)];
      if (suspicious && !sevs.includes('critical')) sevs.push('high');
      const maxSeverity = sevs.reduce<Severity>((m, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[m] ? s : m), 'low');

      const fix = recommendFix(node.version, vulns, published.get(k));
      findings.push({
        fixVersion: fix.version,
        unfixed: fix.unfixed,
        safeFixVersion: fix.safeVersion,
        safeFixCount: fix.safeFixCount,
        ecosystem: graph.ecosystem,
        name: node.name,
        version: node.version,
        key: node.key,
        direct: info.direct,
        dev: !!node.dev,
        via: info.via,
        introducedBy: info.introducedBy,
        vulns: vulns.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]),
        signals: signals.sort((a, b) => b.score - a.score),
        riskScore,
        suspicious,
        maxSeverity,
      });
    }
    return findings.sort((a, b) => SEVERITY_RANK[b.maxSeverity] - SEVERITY_RANK[a.maxSeverity] || Number(b.suspicious) - Number(a.suspicious) || a.name.localeCompare(b.name));
  }
}

function shortName(file: string) {
  return file.split(/[\\/]/).slice(-2).join('/');
}

/** Stable identity of an issue, used to detect *new* findings between scans. */
export function issueIds(results: FileResult[]): Set<string> {
  const ids = new Set<string>();
  for (const r of results) {
    for (const f of r.findings) {
      for (const v of f.vulns) ids.add(`${r.file}|${f.key}|${v.id}`);
      if (f.suspicious) ids.add(`${r.file}|${f.key}|suspicious`);
    }
  }
  return ids;
}
