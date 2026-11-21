import type { Severity } from './types';

const roundUp = (x: number) => {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
};

/** CVSS v3.0/v3.1 base score from a vector string. Returns undefined for unsupported vectors. */
export function cvss3Score(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m: Record<string, string> = {};
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    m[k] = v;
  }
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const scopeChanged = m.S === 'C';
  const PR = scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR] : { N: 0.85, L: 0.62, H: 0.27 }[m.PR];
  const cia = (x: string) => ({ H: 0.56, L: 0.22, N: 0 })[x];
  const C = cia(m.C);
  const I = cia(m.I);
  const A = cia(m.A);
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined)) return undefined;
  const iss = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  if (impact <= 0) return 0;
  return scopeChanged ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10));
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

export function severityFromLabel(label: string | undefined): Severity | undefined {
  switch ((label ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
  }
  return undefined;
}
