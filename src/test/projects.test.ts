import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as path from 'path';
import { discoverScanTargets } from '../core/parsers';
import { groupProjects, statsOf } from '../core/projects';
import type { Ecosystem, FileResult } from '../core/types';

const r = path.resolve('/ws');
const rel = (files: string[]) => files.map((x) => path.relative(r, x).replace(/\\/g, '/')).sort();
const reader = (files: Record<string, string>) => async (p: string) => files[path.relative(r, p).replace(/\\/g, '/')];

test('a project below an unrelated lockfile is still scanned', async () => {
  const files = ['package.json', 'package-lock.json', 'frontend/package.json', 'backend/pom.xml'].map((f) => path.join(r, f));
  const t = await discoverScanTargets(files, reader({ 'package.json': '{"name":"tools","devDependencies":{"prettier":"3"}}' }));
  assert.deepEqual(rel(t), ['backend/pom.xml', 'frontend/package.json', 'package-lock.json']);
});

test('npm, yarn and pnpm workspace members are folded into the root lockfile', async () => {
  const files = ['package.json', 'package-lock.json', 'packages/a/package.json', 'apps/web/package.json', 'apps/legacy/package.json', 'other/package.json'].map((f) => path.join(r, f));
  const t = await discoverScanTargets(files, reader({ 'package.json': '{"workspaces":{"packages":["packages/*","apps/**","!apps/legacy"]}}' }));
  assert.deepEqual(rel(t), ['apps/legacy/package.json', 'other/package.json', 'package-lock.json']);

  const pnpm = ['package.json', 'pnpm-lock.yaml', 'libs/x/package.json', 'demo/package.json'].map((f) => path.join(r, f));
  const t2 = await discoverScanTargets(pnpm, reader({ 'package.json': '{}', 'pnpm-workspace.yaml': "packages:\n  - 'libs/*'\n" }));
  assert.deepEqual(rel(t2), ['demo/package.json', 'pnpm-lock.yaml']);
});

const result = (file: string, ecosystem: Ecosystem, sev?: 'critical' | 'low'): FileResult => ({
  file: path.join(r, file),
  ecosystem,
  packageCount: 10,
  warnings: [],
  scannedAt: '',
  findings: sev
    ? [
        {
          ecosystem,
          name: 'x',
          version: '1',
          key: 'x@1',
          direct: true,
          dev: false,
          via: [],
          signals: [],
          riskScore: 0,
          suspicious: false,
          maxSeverity: sev,
          vulns: [{ id: 'V', aliases: [], summary: '', severity: sev, fixedVersions: [], references: [], url: '', isMalicious: false }],
        },
      ]
    : [],
});

test('results are grouped into projects, worst first', () => {
  const projects = groupProjects(
    [
      result('web/package-lock.json', 'npm', 'low'),
      result('api/pom.xml', 'Maven', 'critical'),
      result('api/core/pom.xml', 'Maven'),
      result('api/ui/package.json', 'npm'),
    ],
    [{ name: 'ws', path: r }],
  );
  assert.deepEqual(
    projects.map((p) => [p.name, p.ecosystem, p.results.length]),
    [
      ['api', 'Maven', 2],
      ['web', 'npm', 1],
      ['api/ui', 'npm', 1],
    ],
  );
  assert.equal(statsOf(projects[0].results).critical, 1);
  assert.equal(projects[0].id, 'project-1');
});

test('root-level projects use the workspace folder name; same folder, two ecosystems are disambiguated', () => {
  const projects = groupProjects([result('pom.xml', 'Maven'), result('package.json', 'npm')], [{ name: 'shop', path: r }]);
  assert.deepEqual(projects.map((p) => p.name).sort(), ['shop (Maven)', 'shop (npm)']);
});
