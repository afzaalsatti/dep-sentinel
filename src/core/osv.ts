import { cvss3Score, severityFromLabel, severityFromScore } from './cvss';
import { createLimiter } from './http';
import { normalizePyName } from './parsers/python';
import type { CoreContext, Ecosystem, Severity, Vulnerability } from './types';

const OSV = 'https://api.osv.dev/v1';

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  modified?: string;
  published?: string;
  withdrawn?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[]; 'malicious-packages-origins'?: unknown };
  affected?: {
    package?: { name: string; ecosystem: string };
    ranges?: { type: string; events: Record<string, string>[] }[];
    ecosystem_specific?: { severity?: string };
    database_specific?: { severity?: string };
  }[];
  references?: { type: string; url: string }[];
}

export interface PackageQuery {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

const qKey = (q: PackageQuery) => `${q.ecosystem}|${q.name}|${q.version}`;

/** Query OSV for many packages. Returns map of query key -> vulnerabilities. */
/** Progress callback: `done` of `total` steps finished in the current OSV phase. */
export type OsvProgress = (phase: 'query' | 'details', done: number, total: number) => void;

export async function queryOsv(queries: PackageQuery[], ctx: CoreContext, onProgress: OsvProgress = () => undefined): Promise<Map<string, Vulnerability[]>> {
  const ids = new Map<string, { id: string; modified?: string }[]>();
  const valid = queries.filter((q) => q.version && q.version !== 'unknown' && !/^(git|file|link|https?|workspace)[:+]/.test(q.version));

  onProgress('query', 0, valid.length);
  for (let i = 0; i < valid.length; i += 1000) {
    if (ctx.isCancelled?.()) break;
    const chunk = valid.slice(i, i + 1000);
    let pending = chunk.map((q, idx) => ({ q, idx, pageToken: undefined as string | undefined }));
    while (pending.length) {
      const body = {
        queries: pending.map(({ q, pageToken }) => ({
          package: { name: q.name, ecosystem: q.ecosystem },
          version: q.version,
          ...(pageToken ? { page_token: pageToken } : {}),
        })),
      };
      const res = await ctx.http.json<{ results: { vulns?: { id: string; modified?: string }[]; next_page_token?: string }[] }>(`${OSV}/querybatch`, {
        method: 'POST',
        body,
        timeoutMs: 60000,
      });
      const next: typeof pending = [];
      res.results.forEach((r, j) => {
        const { q } = pending[j];
        const k = qKey(q);
        if (r.vulns?.length) ids.set(k, [...(ids.get(k) ?? []), ...r.vulns]);
        if (r.next_page_token) next.push({ ...pending[j], pageToken: r.next_page_token });
      });
      pending = next;
    }
    onProgress('query', Math.min(i + 1000, valid.length), valid.length);
  }

  // Fetch details for each unique vuln (cached by id+modified).
  const unique = new Map<string, string | undefined>();
  for (const list of ids.values()) for (const v of list) unique.set(v.id, v.modified);
  const details = new Map<string, OsvVuln>();
  const limit = createLimiter(8);
  let fetched = 0;
  onProgress('details', 0, unique.size);
  await Promise.all(
    [...unique].map(([id, modified]) =>
      limit(async () => {
        const cached = ctx.cache.get<OsvVuln>('osv-vuln', id);
        if (cached && (!modified || cached.modified === modified)) {
          details.set(id, cached);
          return;
        }
        try {
          const v = await ctx.http.json<OsvVuln>(`${OSV}/vulns/${encodeURIComponent(id)}`);
          const slim: OsvVuln = { ...v, details: v.details?.slice(0, 4000) };
          ctx.cache.set('osv-vuln', id, slim, 30 * 24 * 3600_000);
          details.set(id, slim);
        } catch (e) {
          ctx.log.warn(`OSV detail ${id}: ${(e as Error).message}`);
          if (cached) details.set(id, cached);
          else details.set(id, { id, summary: 'Details unavailable (network error)', modified });
        }
      }).finally(() => onProgress('details', ++fetched, unique.size)),
    ),
  );

  const out = new Map<string, Vulnerability[]>();
  for (const q of valid) {
    const list = ids.get(qKey(q));
    if (!list) continue;
    const vulns: Vulnerability[] = [];
    const seen = new Set<string>();
    for (const { id } of list) {
      if (seen.has(id)) continue;
      seen.add(id);
      const d = details.get(id);
      if (!d || d.withdrawn) continue;
      vulns.push(toVulnerability(d, q));
    }
    if (vulns.length) out.set(qKey(q), dedupeAliases(vulns));
  }
  return out;
}

export function osvKey(q: PackageQuery) {
  return qKey(q);
}

function samePackage(a: string, b: string, eco: string): boolean {
  if (eco === 'PyPI') return normalizePyName(a) === normalizePyName(b);
  if (eco === 'Packagist' || eco === 'NuGet') return a.toLowerCase() === b.toLowerCase();
  return a === b;
}

export function toVulnerability(v: OsvVuln, q: PackageQuery): Vulnerability {
  const affected = (v.affected ?? []).filter((a) => a.package && samePackage(a.package.name, q.name, q.ecosystem));
  let score: number | undefined;
  for (const s of v.severity ?? []) {
    const sc = s.type === 'CVSS_V3' ? cvss3Score(s.score) : undefined;
    if (sc !== undefined && (score === undefined || sc > score)) score = sc;
  }
  const label =
    severityFromLabel(v.database_specific?.severity) ??
    affected.map((a) => severityFromLabel(a.database_specific?.severity) ?? severityFromLabel(a.ecosystem_specific?.severity)).find(Boolean);
  const isMalicious =
    v.id.startsWith('MAL-') ||
    !!v.database_specific?.['malicious-packages-origins'] ||
    (v.database_specific?.cwe_ids ?? []).includes('CWE-506') ||
    /^(malicious (code|package|version)|embedded malicious code)\b|\b(contains|includes|ships) (a )?(malware|backdoor)\b|\bcompromised (package|release|version)s?\b/i.test(v.summary ?? '');
  let severity: Severity = score !== undefined ? severityFromScore(score) : label ?? 'unknown';
  if (label && score === undefined) severity = label;
  if (isMalicious) severity = 'critical';

  const fixed = new Set<string>();
  for (const a of affected) for (const r of a.ranges ?? []) for (const e of r.events) if (e.fixed) fixed.add(e.fixed);

  const cve = [v.id, ...(v.aliases ?? [])].find((x) => x.startsWith('CVE-'));
  const ghsa = [v.id, ...(v.aliases ?? [])].find((x) => x.startsWith('GHSA-'));
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary ?? v.details?.split('\n')[0]?.slice(0, 200) ?? v.id,
    details: v.details,
    severity,
    cvssScore: score,
    fixedVersions: [...fixed],
    references: (v.references ?? []).map((r) => r.url).slice(0, 10),
    url: ghsa ? `https://github.com/advisories/${ghsa}` : cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : `https://osv.dev/vulnerability/${v.id}`,
    published: v.published,
    modified: v.modified,
    isMalicious,
  };
}

/** OSV can return GHSA + PYSEC/GO entries describing the same issue – keep one per alias group. */
function dedupeAliases(vulns: Vulnerability[]): Vulnerability[] {
  const out: Vulnerability[] = [];
  const claimed = new Set<string>();
  const pref = (v: Vulnerability) => (v.id.startsWith('MAL-') ? 0 : v.id.startsWith('GHSA-') ? 1 : 2);
  for (const v of [...vulns].sort((a, b) => pref(a) - pref(b))) {
    if (claimed.has(v.id) || v.aliases.some((a) => claimed.has(a))) continue;
    out.push(v);
    claimed.add(v.id);
    v.aliases.forEach((a) => claimed.add(a));
  }
  return out;
}
