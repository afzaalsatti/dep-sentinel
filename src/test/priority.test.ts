import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixAction, priorityOf } from '../core/priority';
import type { PackageFinding, Severity } from '../core/types';

const finding = (o: Partial<PackageFinding> & { sev?: Severity; cvss?: number; malicious?: boolean } = {}): PackageFinding => ({
  ecosystem: 'npm',
  name: 'x',
  version: '1.0.0',
  key: 'x@1.0.0',
  direct: true,
  dev: false,
  via: [],
  signals: [],
  riskScore: 0,
  suspicious: false,
  maxSeverity: o.sev ?? 'high',
  vulns: o.sev || o.malicious
    ? [{ id: 'V', aliases: [], summary: '', severity: o.sev ?? 'critical', cvssScore: o.cvss, fixedVersions: [], references: [], url: '', isMalicious: !!o.malicious }]
    : [],
  ...o,
});

test('priority tiers: runtime vs dev, malicious and suspicious', () => {
  assert.equal(priorityOf(finding({ malicious: true, dev: true })).priority, 'now');
  assert.equal(priorityOf(finding({ sev: 'critical' })).priority, 'now');
  assert.equal(priorityOf(finding({ sev: 'critical', dev: true })).priority, 'soon');
  assert.equal(priorityOf(finding({ sev: 'high' })).priority, 'soon');
  assert.equal(priorityOf(finding({ sev: 'high', dev: true })).priority, 'plan');
  assert.equal(priorityOf(finding({ sev: 'medium' })).priority, 'plan');
  assert.equal(priorityOf(finding({ sev: 'unknown' })).priority, 'plan');
  assert.equal(priorityOf(finding({ sev: 'low' })).priority, 'later');
  assert.equal(priorityOf(finding({ suspicious: true, riskScore: 60, maxSeverity: 'medium' })).priority, 'soon');
});

test('fix type follows the available upgrade', () => {
  assert.equal(fixAction(finding({ malicious: true })), 'remove');
  assert.equal(fixAction(finding({ suspicious: true })), 'review');
  assert.equal(fixAction(finding({ sev: 'high' })), 'nofix');
  assert.equal(fixAction(finding({ sev: 'high', fixVersion: '1.2.0', safeFixVersion: '1.2.0' })), 'quick');
  assert.equal(fixAction(finding({ sev: 'high', fixVersion: '2.0.0', safeFixVersion: '1.2.0' })), 'major');
  assert.equal(fixAction(finding({ sev: 'high', fixVersion: '2.0.0' })), 'major');
});

test('score orders tiers first, then CVSS, then easy fixes and direct deps', () => {
  const s = (o: Parameters<typeof finding>[0]) => priorityOf(finding(o)).score;
  assert.ok(s({ sev: 'critical', dev: false }) > s({ sev: 'high', cvss: 8.9 }), 'tier beats CVSS');
  assert.ok(s({ sev: 'high', cvss: 8.8 }) > s({ sev: 'high', cvss: 7.1, fixVersion: '1.1', safeFixVersion: '1.1' }), 'CVSS within a tier');
  assert.ok(s({ sev: 'high', cvss: 7.5, fixVersion: '1.1', safeFixVersion: '1.1' }) > s({ sev: 'high', cvss: 7.5 }), 'easy fix first');
  assert.ok(s({ sev: 'high', cvss: 7.5 }) > s({ sev: 'high', cvss: 7.5, direct: false }), 'direct first');
  assert.ok(s({ malicious: true, dev: true }) > s({ sev: 'critical', cvss: 10 }), 'malicious always first');
});

test('reasons explain the priority in plain words', () => {
  const r = priorityOf(finding({ sev: 'critical', cvss: 9.8, direct: false, fixVersion: '1.1', safeFixVersion: '1.1' })).reasons;
  assert.deepEqual(r, ['critical severity (CVSS 9.8)', 'ships with the app', 'sub-dependency', 'easy fix available']);
});
