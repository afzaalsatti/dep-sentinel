import * as semver from 'semver';
import { createLimiter } from './http';
import { isTyposquat } from './popular';
import { listPublishedVersions } from './registryVersions';
import { encodeNpmName } from './resolvers/npm';
import type { CoreContext, Ecosystem, PkgNode, Severity, SupplyChainSignal } from './types';

const HOUR = 3600_000;
const DAY = 24 * HOUR;

export interface ReleaseFacts {
  publishedAt?: string;
  prevVersion?: string;
  prevPublishedAt?: string;
  firstPublishedAt?: string;
}

export interface NpmVersionFacts {
  installScripts: string[];
  publisher?: string;
  hasProvenance: boolean;
  deprecated?: string;
  maintainers?: string[];
  publisherEmail?: string;
  maintainerEmails?: string[];
}

export interface SupplyChainInput {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  direct: boolean;
  node: PkgNode;
}

/** Public mail providers: a shared domain there says nothing about belonging to the same organisation. */
const PUBLIC_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com', 'me.com', 'protonmail.com', 'proton.me', 'gmx.de', 'gmx.net', 'qq.com', '163.com', 'users.noreply.github.com']);

/** New publisher uses the same organisation e-mail domain as a previous maintainer (e.g. two @microsoft.com accounts). */
export function sameOrganisation(publisherEmail: string | undefined, previousMaintainerEmails: string[] | undefined): boolean {
  const domain = (e: string) => e.toLowerCase().split('@')[1] ?? '';
  const d = publisherEmail ? domain(publisherEmail) : '';
  if (!d || PUBLIC_MAIL.has(d)) return false;
  return (previousMaintainerEmails ?? []).some((e) => domain(e) === d);
}

const sig = (code: string, severity: Severity, score: number, message: string): SupplyChainSignal => ({ code, severity, score, message });

function ago(ms: number): string {
  if (ms < HOUR) return `${Math.max(1, Math.round(ms / 60000))} min`;
  if (ms < 2 * DAY) return `${Math.round(ms / HOUR)} h`;
  return `${Math.round(ms / DAY)} days`;
}

/** Offline checks based only on lockfile data and the package name. */
export function offlineSignals(input: SupplyChainInput, ctx: CoreContext): SupplyChainSignal[] {
  const out: SupplyChainSignal[] = [];
  const { node, ecosystem, name } = input;
  if (node.source === 'git') out.push(sig('git-source', 'medium', 3, 'Installed directly from a git repository – bypasses registry integrity, provenance and malware scanning.'));
  else if (node.source === 'url') out.push(sig('url-source', 'medium', 3, 'Installed from an arbitrary URL/tarball instead of the package registry.'));

  if (node.resolved && /^https?:\/\//.test(node.resolved)) {
    try {
      const u = new URL(node.resolved);
      const hostPath = `${u.host}${u.pathname}`;
      const allowed = ctx.config.supplyChain.allowedRegistries;
      if (!allowed.some((a) => hostPath.startsWith(a) || u.host === a)) {
        out.push(
          sig('untrusted-registry', 'high', 5, `Resolved from non-allow-listed host "${u.host}" (possible dependency-confusion or lockfile tampering). If this is your company mirror, add it to depSentinel.supplyChain.allowedRegistries.`),
        );
      }
      if (u.protocol === 'http:') out.push(sig('insecure-transport', 'high', 4, 'Resolved over plain HTTP – tarball can be tampered with in transit.'));
    } catch {
      /* not a URL */
    }
  }
  if (ecosystem === 'npm' && node.source === 'registry' && node.resolved && !node.integrity) {
    out.push(sig('missing-integrity', 'low', 1, 'Lockfile entry has no integrity hash – the downloaded tarball is not verified.'));
  }
  if (node.hasInstallScript) {
    out.push(sig('install-script', 'low', 1, 'Runs an install-time script (pre/post-install) – a common malware execution vector.'));
  }
  const target = isTyposquat(ecosystem, name);
  if (target) out.push(sig('typosquat', 'high', 4, `Name is suspiciously similar to popular package "${target}" (possible typosquat).`));
  return out;
}

export class SupplyChainAnalyzer {
  private limit = createLimiter(8);
  constructor(private readonly ctx: CoreContext) {}

  async analyze(inputs: SupplyChainInput[]): Promise<Map<string, SupplyChainSignal[]>> {
    const { ctx } = this;
    const out = new Map<string, SupplyChainSignal[]>();
    const trusted = new Set(ctx.config.supplyChain.trustedPackages.map((t) => t.toLowerCase()));
    const key = (i: SupplyChainInput) => `${i.ecosystem}|${i.name}|${i.version}`;

    const eligible = inputs.filter((i) => !trusted.has(i.name.toLowerCase()) && !trusted.has(`${i.name}@${i.version}`.toLowerCase()));
    for (const i of eligible) out.set(key(i), offlineSignals(i, ctx));

    // Direct deps first, so the most relevant packages are covered if the lookup cap is reached.
    const network = eligible
      .filter((i) => (i.node.source ?? 'registry') === 'registry' && i.version !== 'unknown')
      .sort((a, b) => Number(b.direct) - Number(a.direct))
      .slice(0, ctx.config.supplyChain.maxRegistryLookups);

    await Promise.all(
      network.map((i) =>
        this.limit(async () => {
          if (ctx.isCancelled?.()) return;
          try {
            const signals = await this.networkSignals(i);
            const list = out.get(key(i))!;
            if (signals.some((s) => s.code === 'install-script-added')) {
              const idx = list.findIndex((s) => s.code === 'install-script');
              if (idx >= 0) list.splice(idx, 1);
            }
            for (const s of signals) if (!list.some((x) => x.code === s.code)) list.push(s);
          } catch (e) {
            ctx.log.warn(`Supply-chain lookup ${i.name}@${i.version}: ${(e as Error).message}`);
          }
        }),
      ),
    );
    return out;
  }

  private async networkSignals(i: SupplyChainInput): Promise<SupplyChainSignal[]> {
    const out: SupplyChainSignal[] = [];
    const now = Date.now();
    const recent = this.ctx.config.supplyChain.recentPublishHours * HOUR;
    const facts = await this.releaseFacts(i.ecosystem, i.name, i.version);
    if (facts.publishedAt) {
      const age = now - Date.parse(facts.publishedAt);
      if (age < DAY) out.push(sig('fresh-release', 'high', 4, `This version was published only ${ago(age)} ago. Compromised releases are usually detected within the first days – consider waiting or pinning the previous version.`));
      else if (age < recent) out.push(sig('fresh-release', 'medium', 3, `This version was published ${ago(age)} ago (< ${this.ctx.config.supplyChain.recentPublishHours} h).`));
      if (facts.prevPublishedAt) {
        const gap = Date.parse(facts.publishedAt) - Date.parse(facts.prevPublishedAt);
        if (gap > 365 * DAY && age < 60 * DAY) out.push(sig('dormant-revival', 'medium', 2, `Released after ${Math.round(gap / (30 * DAY))} months of inactivity – typical of hijacked/abandoned packages.`));
      }
    }
    if (facts.firstPublishedAt) {
      const pkgAge = now - Date.parse(facts.firstPublishedAt);
      if (pkgAge < 30 * DAY) out.push(sig('new-package', 'medium', 3, `Package first appeared only ${ago(pkgAge)} ago.`));
    }

    if (i.ecosystem === 'npm') {
      const cur = await this.npmFacts(i.name, i.version);
      if (cur) {
        if (cur.deprecated) out.push(sig('deprecated', 'low', 1, `Deprecated: ${cur.deprecated.slice(0, 160)}`));
        // Release-to-release comparisons only matter for recent versions – older compromised
        // releases are already covered by advisories (OSV / OpenSSF malicious-packages).
        const recentEnough = !facts.publishedAt || now - Date.parse(facts.publishedAt) < 90 * DAY;
        const prev = facts.prevVersion && recentEnough ? await this.npmFacts(i.name, facts.prevVersion) : undefined;
        if (cur.installScripts.length) {
          if (prev && prev.installScripts.length === 0) {
            out.push(sig('install-script-added', 'high', 5, `Adds a new "${cur.installScripts.join('/')}" script that ${facts.prevVersion} did not have – classic malicious-release pattern.`));
          } else if (!i.node.hasInstallScript) {
            out.push(sig('install-script', 'low', 1, `Runs install-time script(s): ${cur.installScripts.join(', ')}.`));
          }
        }
        if (prev) {
          // A different publisher is only interesting if they weren't already a maintainer
          // and the release isn't from a provenance-attested CI pipeline (trusted publishing).
          const knownMaintainer = (!!cur.publisher && (prev.maintainers ?? []).includes(cur.publisher)) || sameOrganisation(cur.publisherEmail, prev.maintainerEmails);
          if (prev.publisher && cur.publisher && prev.publisher !== cur.publisher && !knownMaintainer && !cur.hasProvenance && cur.publisher !== 'GitHub Actions') {
            out.push(sig('publisher-changed', 'medium', 3, `Published by "${cur.publisher}" while ${facts.prevVersion} was published by "${prev.publisher}" (possible account takeover).`));
          }
          if (prev.hasProvenance && !cur.hasProvenance) {
            out.push(sig('provenance-dropped', 'high', 5, `${facts.prevVersion} was published with build provenance (trusted CI), but this version was not – may have been published manually with stolen credentials.`));
          }
        }
      }
    }
    return out;
  }

  /** Publish-time facts. Immutable once the version exists, so cached permanently. */
  async releaseFacts(eco: Ecosystem, name: string, version: string): Promise<ReleaseFacts> {
    const cacheKey = `${eco}|${name}@${version}`;
    const cached = this.ctx.cache.get<ReleaseFacts>('release-facts', cacheKey);
    if (cached) return cached;
    let versions = await listPublishedVersions(this.ctx, eco, name);

    let current = versions?.find((v) => v.version === version || v.version === `v${version}`);
    if (!current?.publishedAt) {
      // Very fresh versions may not be indexed by deps.dev yet – ask the registry directly.
      const fresh = await this.registryPublishTime(eco, name, version);
      if (fresh) {
        current = { version, publishedAt: fresh };
        versions = [...(versions ?? []), current];
      }
    }
    const facts: ReleaseFacts = { publishedAt: current?.publishedAt };
    if (versions?.length) {
      const dated = versions.filter((v) => v.publishedAt).sort((a, b) => Date.parse(a.publishedAt!) - Date.parse(b.publishedAt!));
      facts.firstPublishedAt = dated[0]?.publishedAt;
      let prev: { version: string; publishedAt?: string } | undefined;
      if (semver.valid(version, { loose: true })) {
        prev = dated
          .filter((v) => semver.valid(v.version, { loose: true }) && !semver.prerelease(v.version, { loose: true }) && semver.lt(v.version, version, { loose: true }))
          .sort((a, b) => semver.rcompare(a.version, b.version, { loose: true }))[0];
      } else if (current?.publishedAt) {
        prev = dated.filter((v) => Date.parse(v.publishedAt!) < Date.parse(current!.publishedAt!)).pop();
      }
      facts.prevVersion = prev?.version;
      facts.prevPublishedAt = prev?.publishedAt;
    }
    // Facts for an unknown publish date may appear later; otherwise they never change.
    this.ctx.cache.set('release-facts', cacheKey, facts, facts.publishedAt ? undefined : HOUR);
    return facts;
  }

  private async registryPublishTime(eco: Ecosystem, name: string, version: string): Promise<string | undefined> {
    try {
      if (eco === 'npm') {
        const doc = await this.ctx.http.jsonOrUndefined<{ time?: Record<string, string> }>(`${this.ctx.config.npmRegistry.replace(/\/$/, '')}/${encodeNpmName(name)}`);
        return doc?.time?.[version];
      }
      if (eco === 'PyPI') {
        const doc = await this.ctx.http.jsonOrUndefined<{ urls?: { upload_time_iso_8601?: string }[] }>(`https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`);
        return doc?.urls?.[0]?.upload_time_iso_8601;
      }
    } catch {
      /* ignore */
    }
    return undefined;
  }

  async npmFacts(name: string, version: string): Promise<NpmVersionFacts | undefined> {
    const cacheKey = `${name}@${version}`;
    const cached = this.ctx.cache.get<NpmVersionFacts | null>('npm-version-v2', cacheKey);
    if (cached !== undefined) return cached ?? undefined;
    const m = await this.ctx.http.jsonOrUndefined<{
      scripts?: Record<string, string>;
      _npmUser?: { name?: string; email?: string };
      dist?: { attestations?: { provenance?: unknown } };
      deprecated?: string;
      maintainers?: { name?: string; email?: string }[];
    }>(`${this.ctx.config.npmRegistry.replace(/\/$/, '')}/${encodeNpmName(name)}/${encodeURIComponent(version)}`);
    const facts: NpmVersionFacts | null = m
      ? {
          installScripts: ['preinstall', 'install', 'postinstall'].filter((s) => m.scripts?.[s]),
          publisher: m._npmUser?.name,
          publisherEmail: m._npmUser?.email,
          hasProvenance: !!m.dist?.attestations?.provenance,
          deprecated: typeof m.deprecated === 'string' ? m.deprecated : undefined,
          maintainers: (m.maintainers ?? []).map((x) => x.name ?? '').filter(Boolean),
          maintainerEmails: (m.maintainers ?? []).map((x) => x.email ?? '').filter(Boolean),
        }
      : null;
    this.ctx.cache.set('npm-version-v2', cacheKey, facts, 7 * DAY);
    return facts ?? undefined;
  }
}
