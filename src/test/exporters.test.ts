import assert from 'node:assert/strict';
import { test } from 'node:test';
import { findingSeverity, toMarkdown, toSarif } from '../core/exporters';
import type { FileResult, PackageFinding, Vulnerability } from '../core/types';

const vuln = (id: string, severity: Vulnerability['severity'], extra: Partial<Vulnerability> = {}): Vulnerability => ({
  id, aliases: ['CVE-2021-1'], summary: `Issue ${id}`, severity, fixedVersions: ['1.2.6'], references: [], url: `https://github.com/advisories/${id}`, isMalicious: false, ...extra,
});
const finding = (name: string, extra: Partial<PackageFinding>): PackageFinding => ({
  ecosystem: 'npm', name, version: '1.0.0', key: `${name}@1.0.0`, direct: true, dev: false, via: [], vulns: [], signals: [], riskScore: 0, suspicious: false, maxSeverity: 'low', ...extra,
});
const root = process.platform === 'win32' ? 'C:\\proj' : '/proj';
const file = (rel: string) => `${root}${process.platform === 'win32' ? '\\' : '/'}${rel}`;

const results: FileResult[] = [
  {
    file: file('package-lock.json'),
    ecosystem: 'npm',
    packageCount: 3,
    scannedAt: '',
    warnings: [],
    findings: [
      finding('minimist', { vulns: [vuln('GHSA-a', 'critical')], fixVersion: '1.2.6', safeFixVersion: '1.2.6', safeFixCount: 1, unfixed: [] }),
      finding('flatmap-stream', { direct: false, via: ['event-stream@3.3.6'], vulns: [vuln('MAL-1', 'critical', { isMalicious: true })], suspicious: true }),
      finding('left|pad', { suspicious: true, riskScore: 6, signals: [{ code: 'fresh-release', severity: 'high', score: 4, message: 'new' }, { code: 'install-script', severity: 'low', score: 1, message: 'x' }] }),
    ],
  },
];

test('findingSeverity', () => {
  assert.equal(findingSeverity(results[0].findings[0]), 'critical');
  assert.equal(findingSeverity(results[0].findings[1]), 'critical');
  assert.equal(findingSeverity(results[0].findings[2]), 'high'); // suspicious only
  assert.equal(findingSeverity(finding('x', {})), 'low');
});

test('markdown report: summary, malicious section, escaped table cells, fix advice', () => {
  const md = toMarkdown(results, root, new Date('2026-11-21T10:00:00Z'));
  assert.match(md, /^# Dependency security report/);
  assert.match(md, /\| 1 \| 1 \| 0 \| 0 \| 0 \| 1 \|/); // malicious, critical, high, medium, low, suspicious
  assert.match(md, /## ☠ Malicious packages – remove immediately\n\n- \*\*flatmap-stream@1\.0\.0\*\* \(via event-stream@3\.3\.6\)/);
  assert.match(md, /\| Fix now \| CRITICAL \| `minimist@1\.0\.0` \| direct \| \[CVE-2021-1\]\(https:\/\/github\.com\/advisories\/GHSA-a\) \| Upgrade to 1\.2\.6\. \|/);
  assert.match(md, /`left\\\|pad@1\.0\.0` ⚠/, 'pipes in names must be escaped');
  assert.match(md, /⚠ Suspicious: fresh-release \|/);
  assert.ok(!/flatmap-stream@1\.0\.0` /.test(md), 'malicious packages are not repeated in the file tables');
});

test('sarif export structure', async () => {
  const s = (await toSarif(results, root)) as { version: string; runs: { results: { ruleId: string; level: string; locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[]; tool: { driver: { rules: { id: string }[] } } }[] };
  assert.equal(s.version, '2.1.0');
  const r = s.runs[0];
  assert.deepEqual(r.results.map((x) => x.ruleId).sort(), ['DEPSENTINEL-SUSPICIOUS', 'GHSA-a', 'MAL-1']);
  assert.ok(r.results.every((x) => x.level === 'error'));
  assert.equal(r.results[0].locations[0].physicalLocation.artifactLocation.uri, 'package-lock.json');
});
