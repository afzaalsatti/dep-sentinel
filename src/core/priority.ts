import { EPSS_LIKELY, pct } from './exploit';
import type { PackageFinding, Severity } from './types';
import { SEVERITY_RANK } from './types';

/** How urgently a finding should be handled. */
export type Priority = 'now' | 'soon' | 'plan' | 'later';
/** What fixing it takes. */
export type FixAction = 'remove' | 'quick' | 'major' | 'nofix' | 'review';

export const PRIORITY_LABEL: Record<Priority, string> = { now: 'Fix now', soon: 'Fix soon', plan: 'Plan', later: 'Later' };
export const PRIORITY_HINT: Record<Priority, string> = {
  now: 'Malicious, exploited in the wild, or critical in code that ships',
  soon: 'High severity or likely to be exploited, critical or exploited in dev tooling, or suspicious',
  plan: 'Medium severity, or high in dev tooling',
  later: 'Low severity',
};
export const PRIORITY_ORDER: Priority[] = ['now', 'soon', 'plan', 'later'];

export const FIX_LABEL: Record<FixAction, string> = {
  remove: 'Remove now',
  quick: 'Quick win: same-major upgrade',
  major: 'Major upgrade needed',
  nofix: 'No fix yet',
  review: 'Review package',
};
export const FIX_ORDER: FixAction[] = ['remove', 'quick', 'major', 'nofix', 'review'];

export interface PriorityInfo {
  priority: Priority;
  fix: FixAction;
  /** Higher = handle first. Comparable across all findings. */
  score: number;
  /** Highest CVSS score among the advisories, if any is known. */
  cvss?: number;
  /** Listed in CISA KEV: exploitation in the wild is confirmed. */
  exploited: boolean;
  /** Used in ransomware campaigns (CISA KEV). */
  ransomware: boolean;
  /** Highest EPSS probability (0-1) among the advisories, if known. */
  epss?: number;
  /** Short, plain reasons behind the priority, most important first. */
  reasons: string[];
}

const isMalicious = (f: PackageFinding) => f.vulns.some((v) => v.isMalicious);

/** Highest severity among the package's (non-malicious) advisories, ignoring supply-chain signals. */
function vulnSeverity(f: PackageFinding): Severity | undefined {
  let best: Severity | undefined;
  for (const v of f.vulns) if (!v.isMalicious && (!best || SEVERITY_RANK[v.severity] > SEVERITY_RANK[best])) best = v.severity;
  return best;
}

export function fixAction(f: PackageFinding): FixAction {
  if (isMalicious(f)) return 'remove';
  if (!f.vulns.length) return 'review';
  if (!f.fixVersion) return 'nofix';
  return f.safeFixVersion && f.safeFixVersion === f.fixVersion ? 'quick' : 'major';
}

export function priorityOf(f: PackageFinding): PriorityInfo {
  const sev = vulnSeverity(f);
  const rank = sev ? SEVERITY_RANK[sev] : 0;
  const fix = fixAction(f);
  const scores = f.vulns.map((v) => v.cvssScore).filter((s): s is number => s !== undefined);
  const cvss = scores.length ? Math.max(...scores) : undefined;

  const exploited = f.vulns.some((v) => v.kev);
  const ransomware = f.vulns.some((v) => v.kev?.ransomware);
  const epssScores = f.vulns.map((v) => v.epss?.score).filter((s): s is number => s !== undefined);
  const epss = epssScores.length ? Math.max(...epssScores) : undefined;
  const likely = epss !== undefined && epss >= EPSS_LIKELY;

  let tier: number; // index into PRIORITY_ORDER
  if (isMalicious(f) || (rank === 4 && !f.dev)) tier = 0;
  else if ((rank === 3 && !f.dev) || rank === 4 || f.suspicious) tier = 1;
  else if (rank === 2 || rank === 3) tier = 2;
  else tier = 3;
  // Real-world exploitation outranks theoretical severity. Dev tooling is capped at "soon": it does not ship to users.
  if (exploited) tier = Math.min(tier, f.dev ? 1 : 0);
  else if (likely) tier = Math.min(tier, Math.max(f.dev ? 1 : 0, tier - 1));
  const priority = PRIORITY_ORDER[Math.max(0, Math.min(tier, 3))];

  const reasons: string[] = [];
  if (isMalicious(f)) reasons.push('known malicious package');
  if (exploited) reasons.push(ransomware ? 'exploited in the wild, used by ransomware (CISA KEV)' : 'exploited in the wild (CISA KEV)');
  else if (likely) reasons.push(`likely to be exploited soon (EPSS ${pct(epss!)})`);
  if (!isMalicious(f) && sev) reasons.push(`${sev === 'unknown' ? 'unrated' : sev} severity${cvss !== undefined ? ` (CVSS ${cvss})` : ''}`);
  if (f.suspicious && !isMalicious(f)) reasons.push(`supply-chain risk ${f.riskScore}`);
  reasons.push(f.dev ? 'dev tooling only' : 'ships with the app');
  reasons.push(f.direct ? 'direct dependency' : 'sub-dependency');
  if (fix === 'quick') reasons.push('easy fix available');
  else if (fix === 'major') reasons.push('fix needs a major upgrade');
  else if (fix === 'nofix') reasons.push('no fix published');
  if (f.vulns.length > 1) reasons.push(`${f.vulns.length} advisories`);
  if (!exploited && !likely && epss !== undefined) reasons.push(`low exploit likelihood (EPSS ${pct(epss)})`);

  // Within a tier: worse CVSS first, then easy fixes (most risk removed per minute), then direct deps, then more advisories.
  const score =
    (4 - PRIORITY_ORDER.indexOf(priority)) * 100_000 +
    (isMalicious(f) ? 50_000 : 0) +
    (exploited ? 3_000 : 0) +
    (ransomware ? 500 : 0) +
    Math.round((epss ?? 0) * 2_000) +
    Math.round((cvss ?? [0, 2, 5, 7.5, 9.5][rank]) * 100) +
    (fix === 'quick' ? 60 : fix === 'major' ? 30 : 0) +
    (f.direct ? 20 : 0) +
    Math.min(f.vulns.length, 10) * 2 +
    Math.min(f.riskScore, 100) / 10;

  return { priority, fix, score, cvss, exploited, ransomware, epss, reasons };
}

