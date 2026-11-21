import { promises as fs } from 'fs';
import * as path from 'path';
import { locatePackage } from './locate';
import { FileResult, PackageFinding, SEVERITY_RANK, Severity } from './types';
import { describeFixText } from './versions';
import { safeExternalUrl } from './http';

export const TOOL_VERSION = '1.0.0';

/** Effective severity of a finding: malicious = critical, suspicious ≥ high. */
export function findingSeverity(f: PackageFinding): Severity {
  if (f.vulns.some((v) => v.isMalicious)) return 'critical';
  if (!f.vulns.length && !f.suspicious) return 'low';
  let s: Severity = f.vulns.reduce<Severity>((m, v) => (SEVERITY_RANK[v.severity] > SEVERITY_RANK[m] ? v.severity : m), 'low');
  if (f.suspicious && SEVERITY_RANK.high > SEVERITY_RANK[s]) s = 'high';
  return s;
}

const nameOfKey = (key: string) => {
  const at = key.lastIndexOf('@');
  return at > 0 ? key.slice(0, at) : key;
};

function origin(f: PackageFinding, sep = ' › '): string {
  if (f.direct) return 'direct';
  return f.via.length ? `via ${f.via.join(sep)}` : 'transitive';
}

/** SARIF 2.1.0 – one rule per advisory (and one for suspicious packages), results located on the manifest line. */
export async function toSarif(results: FileResult[], root: string): Promise<object> {
  const rules = new Map<string, object>();
  const sarifResults: object[] = [];
  const level = (s: Severity) => (s === 'critical' || s === 'high' ? 'error' : s === 'low' ? 'note' : 'warning');
  const texts = new Map<string, string | undefined>();
  const lineIn = async (file: string, name: string) => {
    if (!texts.has(file)) texts.set(file, await fs.readFile(file, 'utf8').catch(() => undefined));
    const t = texts.get(file);
    return t ? (locatePackage(t, file, name) ?? 0) + 1 : 1;
  };

  for (const r of results) {
    const file = r.manifestFile ?? r.file;
    const uri = path.relative(root, file).replace(/\\/g, '/');
    for (const f of r.findings) {
      const line = await lineIn(file, f.direct ? f.name : f.introducedBy ? nameOfKey(f.introducedBy) : f.name);
      const location = [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line } } }];
      const from = f.direct ? 'direct dependency' : `transitive via ${f.via.join(' > ') || 'unknown path'}`;
      for (const v of f.vulns) {
        if (!rules.has(v.id)) {
          rules.set(v.id, {
            id: v.id,
            name: v.id,
            shortDescription: { text: v.summary.slice(0, 200) },
            helpUri: safeExternalUrl(v.url),
            help: { text: `${v.summary}\n\nAliases: ${v.aliases.join(', ') || '-'}\nFixed in: ${v.fixedVersions.join(', ') || 'no fix yet'}` },
            properties: { tags: ['security', 'dependency', ...(v.isMalicious ? ['malicious'] : [])], ...(v.cvssScore !== undefined ? { 'security-severity': String(v.cvssScore) } : {}) },
          });
        }
        sarifResults.push({
          ruleId: v.id,
          level: v.isMalicious ? 'error' : level(v.severity),
          message: { text: `${f.name}@${f.version} (${from}): ${v.summary}. ${describeFixText(f)}` },
          locations: location,
          partialFingerprints: { dependency: `${f.key}|${v.id}` },
        });
      }
      if (f.suspicious && !f.vulns.some((v) => v.isMalicious)) {
        const id = 'DEPSENTINEL-SUSPICIOUS';
        if (!rules.has(id)) rules.set(id, { id, name: 'SuspiciousDependency', shortDescription: { text: 'Dependency shows supply-chain attack indicators' }, properties: { tags: ['security', 'supply-chain'], 'security-severity': '7.5' } });
        sarifResults.push({
          ruleId: id,
          level: 'error',
          message: { text: `${f.name}@${f.version} (${from}) is suspicious (risk ${f.riskScore}): ${f.signals.map((s) => s.message).join(' | ')}` },
          locations: location,
          partialFingerprints: { dependency: `${f.key}|suspicious` },
        });
      }
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'DepSentinel', version: TOOL_VERSION, informationUri: 'https://osv.dev', rules: [...rules.values()] } }, results: sarifResults }],
  };
}

/** Escape text for a Markdown table cell; neutralise raw HTML (advisory text and package names are untrusted). */
const md = (s: string) => s.replace(/</g, '&lt;').replace(/\|/g, '\\|').replace(/`/g, "'").replace(/\r?\n/g, ' ');

/** Markdown link to an advisory, or plain text if the URL is not a vetted http(s) link. */
const link = (text: string, url: string) => {
  const safe = safeExternalUrl(url);
  return safe ? `[${md(text).replace(/[[\]]/g, '')}](${safe.replace(/\(/g, '%28').replace(/\)/g, '%29')})` : md(text);
};

/** Markdown report – suited for sharing in a PR, ticket or chat. */
export function toMarkdown(results: FileResult[], root: string, scannedAt = new Date()): string {
  const findings = results.flatMap((r) => r.findings.map((f) => ({ r, f })));
  const vulnCount = (s: Severity) => findings.reduce((n, { f }) => n + f.vulns.filter((v) => v.severity === s && !v.isMalicious).length, 0);
  const malicious = findings.filter(({ f }) => f.vulns.some((v) => v.isMalicious));
  const suspicious = findings.filter(({ f }) => f.suspicious && !f.vulns.some((v) => v.isMalicious));
  const packages = results.reduce((n, r) => n + r.packageCount, 0);
  const out: string[] = [];
  out.push('# Dependency security report', '');
  out.push(`Scanned ${scannedAt.toISOString().replace('T', ' ').slice(0, 16)} UTC · ${results.length} manifest(s) · ${packages} packages (including transitive)`, '');
  out.push('| Malicious | Critical | High | Medium | Low | Suspicious |', '|---|---|---|---|---|---|');
  out.push(`| ${malicious.length} | ${vulnCount('critical')} | ${vulnCount('high')} | ${vulnCount('medium') + vulnCount('unknown')} | ${vulnCount('low')} | ${suspicious.length} |`, '');

  if (malicious.length) {
    out.push('## ☠ Malicious packages – remove immediately', '');
    for (const { r, f } of malicious) out.push(`- **${f.name}@${f.version}** (${origin(f)}) in \`${path.relative(root, r.file).replace(/\\/g, '/')}\` – ${f.vulns.filter((v) => v.isMalicious).map((v) => link(v.id, v.url)).join(', ')}`);
    out.push('', 'Rotate any credentials, tokens and keys on machines where these were installed.', '');
  }

  for (const r of results) {
    const list = r.findings.filter((f) => !f.vulns.some((v) => v.isMalicious));
    if (!list.length) continue;
    out.push(`## \`${path.relative(root, r.file).replace(/\\/g, '/')}\` (${r.ecosystem})`, '');
    out.push('| Severity | Package | Origin | Advisories | Recommended fix |', '|---|---|---|---|---|');
    for (const f of list) {
      const sev = findingSeverity(f);
      const adv = f.vulns.slice(0, 4).map((v) => link(v.aliases.find((a) => a.startsWith('CVE-')) ?? v.id, v.url)).join(', ') + (f.vulns.length > 4 ? ` +${f.vulns.length - 4}` : '');
      const fix = f.vulns.length ? describeFixText(f) : f.suspicious ? `⚠ Suspicious: ${f.signals.filter((s) => s.score >= 3).map((s) => s.code).join(', ')}` : '';
      out.push(`| ${sev.toUpperCase()} | \`${md(f.name)}@${md(f.version)}\`${f.suspicious ? ' ⚠' : ''} | ${md(origin(f, ' → '))}${f.dev ? ' (dev)' : ''} | ${adv || '–'} | ${md(fix)} |`);
    }
    out.push('');
  }
  if (!findings.length) out.push('✅ No known vulnerabilities or suspicious packages found.', '');
  const notes = results.filter((r) => r.error || r.warnings.length);
  if (notes.length) {
    out.push('<details><summary>Notes</summary>', '');
    for (const r of notes) out.push(`- \`${path.relative(root, r.file).replace(/\\/g, '/')}\`: ${md([r.error, ...r.warnings].filter(Boolean).join(' · '))}`);
    out.push('', '</details>', '');
  }
  out.push('_Generated by DepSentinel · sources: OSV.dev, deps.dev, npm registry_');
  return out.join('\n');
}
