import type { PackageFinding, Vulnerability } from './types';

/** One-sentence fix advice for a finding, shared by the extension and the CLI. */
export function describeFixText(f: PackageFinding): string {
  if (!f.vulns.length) return '';
  if (f.vulns.some((v) => v.isMalicious)) return 'Remove this package.';
  if (!f.fixVersion) return 'No fixed version available yet.';
  const n = f.vulns.length;
  const noFix = f.unfixed?.length ? ` ${f.unfixed.length} advisor${f.unfixed.length > 1 ? 'ies have' : 'y has'} no fix yet.` : '';
  const verb = f.direct ? 'Upgrade to' : `Force ${f.name} to`;
  const tail = f.direct ? '' : ' (or upgrade the parent dependency)';
  if (f.safeFixVersion && f.safeFixVersion === f.fixVersion) return `${verb} ${f.fixVersion}${tail}.${noFix}`;
  if (f.safeFixVersion) {
    return `${verb} ${f.safeFixVersion}${tail} – same major, fixes ${f.safeFixCount} of ${n}; ${f.fixVersion} fixes all (major upgrade).${noFix}`;
  }
  return `Only fixed in ${f.fixVersion} (major upgrade${f.direct ? '' : ' of a transitive dependency – upgrade the parent instead'}).${noFix}`;
}

/**
 * Ecosystem-agnostic version comparison (good enough for semver, Maven, PEP 440, Go, Cargo, RubyGems, NuGet).
 * Numeric parts compare numerically; pre-release qualifiers sort before the release; "RELEASE"/"Final"/"GA" equal the release.
 */
type Token = number | string;

const QUALIFIER_RANK: Record<string, number> = {
  dev: -6, snapshot: -5, alpha: -4, a: -4, beta: -3, b: -3, milestone: -2, m: -2, preview: -2, rc: -1, cr: -1, c: -1, pre: -1,
  '': 0, ga: 0, final: 0, release: 0, sp: 1, post: 1,
};

function tokenize(v: string): Token[] {
  const s = v.trim().replace(/^v(?=\d)/i, '').replace(/\+.*$/, '');
  const out: Token[] = [];
  for (const part of s.split(/[.\-_~]/)) {
    for (const m of part.matchAll(/\d+|[a-zA-Z]+/g)) out.push(/^\d+$/.test(m[0]) ? Number(m[0]) : m[0].toLowerCase());
  }
  return out;
}

function qualRank(t: string): number {
  return QUALIFIER_RANK[t] ?? -0.5; // unknown qualifiers are treated as pre-release
}

function compareTokens(x: Token | undefined, y: Token | undefined): number {
  // Pad the shorter version: a missing numeric part is 0, a missing qualifier is "release".
  if (x === undefined) x = typeof y === 'number' ? 0 : '';
  if (y === undefined) y = typeof x === 'number' ? 0 : '';
  if (x === y) return 0;
  if (typeof x === 'number' && typeof y === 'number') return x < y ? -1 : 1;
  if (typeof x === 'number') return 1; // 1.0.1 > 1.0-beta
  if (typeof y === 'number') return -1;
  const d = qualRank(x) - qualRank(y);
  if (d !== 0) return d < 0 ? -1 : 1;
  if (x in QUALIFIER_RANK && y in QUALIFIER_RANK) return 0; // e.g. "" vs "RELEASE"
  return x < y ? -1 : 1;
}

export function compareVersions(a: string, b: string): number {
  const ta = tokenize(a);
  const tb = tokenize(b);
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const c = compareTokens(ta[i], tb[i]);
    if (c !== 0) return c;
  }
  return 0;
}

/** "Major" release line: first numeric part, or first two for 0.x (semver treats 0.y as breaking). */
export function releaseLine(v: string): string {
  const nums = tokenize(v).filter((t): t is number => typeof t === 'number');
  return nums[0] === 0 ? `0.${nums[1] ?? 0}` : String(nums[0] ?? '');
}

export interface FixRecommendation {
  /** Lowest version that fixes every fixable advisory (may be a new major). */
  version?: string;
  /** Advisories with no fixed version above the current one. */
  unfixed: string[];
  /** Best version on the current major line (fixes `safeFixCount` advisories); undefined if none is fixable there. */
  safeVersion?: string;
  safeFixCount: number;
}

const max = (a: string | undefined, b: string) => (!a || compareVersions(b, a) > 0 ? b : a);

/**
 * For each advisory pick the nearest fixed version above `current`; the overall recommendation is the highest of those.
 * Also compute the best upgrade that stays on the current major line, which is usually the safer change.
 */
export function recommendFix(current: string, vulns: Vulnerability[], published?: Set<string>): FixRecommendation {
  let best: string | undefined;
  let safe: string | undefined;
  let safeFixCount = 0;
  const unfixed: string[] = [];
  const line = releaseLine(current);
  // Advisories sometimes list fixes that were never publicly released (e.g. commercial-only backports);
  // when the published version list is known, only recommend versions that can actually be installed.
  const installable = (f: string) => !published || published.has(f.replace(/^v(?=\d)/, ''));
  for (const v of vulns) {
    const candidates = v.fixedVersions.filter((f) => compareVersions(f, current) > 0 && installable(f)).sort(compareVersions);
    if (!candidates.length) {
      unfixed.push(v.id);
      continue;
    }
    best = max(best, candidates[0]);
    const sameLine = candidates.find((c) => releaseLine(c) === line);
    if (sameLine) {
      safe = max(safe, sameLine);
      safeFixCount++;
    }
  }
  return { version: best, unfixed, safeVersion: safe, safeFixCount };
}
