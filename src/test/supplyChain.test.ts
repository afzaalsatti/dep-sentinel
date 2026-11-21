import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MemoryCache } from '../core/cache';
import { SupplyChainAnalyzer } from '../core/supplyChain';
import type { CoreContext } from '../core/types';

function ctxWith(routes: Record<string, unknown>): CoreContext {
  const http = {
    jsonOrUndefined: async (url: string) => {
      for (const [k, v] of Object.entries(routes)) if (url.endsWith(k)) return v;
      return undefined;
    },
  };
  return {
    cache: new MemoryCache(),
    http: http as unknown as CoreContext['http'],
    log: { info() {}, warn() {}, error() {} },
    readFile: async () => undefined,
    config: {
      includeDev: true,
      resolveTransitive: true,
      maxDepth: 5,
      mavenRepos: [],
      npmRegistry: 'https://registry.npmjs.org',
      ignoredAdvisories: [],
      minimumSeverity: 'low',
      supplyChain: { enabled: true, recentPublishHours: 72, threshold: 5, allowedRegistries: ['registry.npmjs.org'], trustedPackages: [], maxRegistryLookups: 100 },
    },
  };
}

const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const DAY = 86400_000;

test('hijacked release: fresh + install script added + publisher change + provenance dropped', async () => {
  const ctx = ctxWith({
    '/systems/npm/packages/chalkish': {
      versions: [
        { versionKey: { version: '5.0.0' }, publishedAt: iso(900 * DAY) },
        { versionKey: { version: '5.0.1' }, publishedAt: iso(400 * DAY) },
        { versionKey: { version: '5.0.2' }, publishedAt: iso(2 * 3600_000) },
      ],
    },
    '/chalkish/5.0.2': { scripts: { postinstall: 'node x.js' }, _npmUser: { name: 'attacker' }, maintainers: [{ name: 'owner' }], dist: {} },
    '/chalkish/5.0.1': { scripts: {}, _npmUser: { name: 'owner' }, maintainers: [{ name: 'owner' }], dist: { attestations: { provenance: { predicateType: 'x' } } } },
  });
  const res = await new SupplyChainAnalyzer(ctx).analyze([
    { ecosystem: 'npm', name: 'chalkish', version: '5.0.2', direct: true, node: { key: 'chalkish@5.0.2', name: 'chalkish', version: '5.0.2', deps: [], source: 'registry', integrity: 'sha512-x', resolved: 'https://registry.npmjs.org/chalkish/-/chalkish-5.0.2.tgz' } },
  ]);
  const signals = res.get('npm|chalkish|5.0.2')!;
  const codes = signals.map((s) => s.code).sort();
  assert.deepEqual(codes, ['dormant-revival', 'fresh-release', 'install-script-added', 'provenance-dropped', 'publisher-changed']);
  assert.ok(signals.reduce((n, s) => n + s.score, 0) >= 5);
});

test('old, stable release with a co-maintainer publishing produces no signals', async () => {
  const ctx = ctxWith({
    '/systems/npm/packages/stable': {
      versions: [
        { versionKey: { version: '1.0.0' }, publishedAt: iso(800 * DAY) },
        { versionKey: { version: '1.0.1' }, publishedAt: iso(700 * DAY) },
      ],
    },
    '/stable/1.0.1': { _npmUser: { name: 'bob' }, maintainers: [{ name: 'alice' }, { name: 'bob' }], dist: {} },
    '/stable/1.0.0': { _npmUser: { name: 'alice' }, maintainers: [{ name: 'alice' }, { name: 'bob' }], dist: {} },
  });
  const res = await new SupplyChainAnalyzer(ctx).analyze([
    { ecosystem: 'npm', name: 'stable', version: '1.0.1', direct: true, node: { key: 'stable@1.0.1', name: 'stable', version: '1.0.1', deps: [], source: 'registry', integrity: 'sha512-x', resolved: 'https://registry.npmjs.org/stable/-/stable-1.0.1.tgz' } },
  ]);
  assert.deepEqual(res.get('npm|stable|1.0.1'), []);
});

test('trusted packages are skipped', async () => {
  const ctx = ctxWith({});
  ctx.config.supplyChain.trustedPackages = ['expres'];
  const res = await new SupplyChainAnalyzer(ctx).analyze([{ ecosystem: 'npm', name: 'expres', version: '1.0.0', direct: true, node: { key: 'expres@1.0.0', name: 'expres', version: '1.0.0', deps: [] } }]);
  assert.equal(res.size, 0);
});
