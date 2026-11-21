/**
 * Security regression tests: each test plays the role of a hostile repository or a hostile server.
 */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { promises as fs } from 'fs';
import * as http from 'http';
import type { AddressInfo } from 'net';
import * as os from 'os';
import * as path from 'path';
import { toMarkdown } from '../core/exporters';
import { readTextFile } from '../core/fsutil';
import { Http, isAllowedUrl, safeExternalUrl } from '../core/http';
import { parseCargoLock } from '../core/parsers/misc';
import { interpolate, isInsideRoots, parsePom } from '../core/resolvers/maven';
import { parseToml } from '../core/toml';
import type { FileResult } from '../core/types';

test('TOML: prototype-pollution payloads are rejected and Object.prototype stays clean', () => {
  const payloads = ['[__proto__]\npolluted = "yes"\n', '[a.__proto__]\npolluted = "yes"\n', '__proto__.polluted = "yes"\n', '[[constructor.prototype]]\npolluted = "yes"\n', 'x = { __proto__ = { polluted = "yes" } }\n'];
  for (const p of payloads) {
    assert.throws(() => parseToml(p), /Unsafe TOML key/, p);
    assert.equal(({} as Record<string, unknown>).polluted, undefined, `polluted by: ${p}`);
  }
  // A malicious Cargo.lock fails as a file error instead of polluting the extension host.
  assert.throws(() => parseCargoLock('/p/Cargo.lock', '[[package]]\nname = "a"\nversion = "1"\n[__proto__]\npolluted = 1\n'));
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  // Normal tables still behave like objects for lookups.
  assert.equal((parseToml('[package]\nname = "x"\n').package as Record<string, string>).name, 'x');
});

test('POM: DOCTYPE entities are not expanded (billion laughs / XXE) and property lookups are own-only', () => {
  // Billion laughs: internal entities must not be expanded.
  const lol = '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>';
  const t = Date.now();
  const pom = parsePom(`<?xml version="1.0"?>${lol}<project><artifactId>&lol3;</artifactId><version>1</version></project>`);
  assert.ok(Date.now() - t < 1000, 'parsing must not blow up');
  assert.ok(!/lollollol/.test(pom.artifactId), `entity expanded: ${pom.artifactId}`);
  // XXE: an external entity must never be resolved – refusing the whole file is the expected outcome.
  const xxe = '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><project><groupId>&xxe;</groupId></project>';
  let parsed: ReturnType<typeof parsePom> | undefined;
  try {
    parsed = parsePom(xxe);
  } catch (e) {
    assert.match((e as Error).message, /external entit/i);
  }
  assert.ok(!/root:/.test(parsed?.groupId ?? ''), 'external entity resolved');
  assert.equal(interpolate('${constructor}', parsePom('<project><properties><a>1</a></properties></project>').properties), '${constructor}');
  assert.equal(interpolate('${toString}', {}), '${toString}');
});

test('POM <relativePath> cannot escape the workspace', () => {
  const root = path.resolve('/work/repo');
  assert.equal(isInsideRoots(path.join(root, 'module/pom.xml'), [root]), true);
  assert.equal(isInsideRoots(path.resolve(root, '../../etc/passwd'), [root]), false);
  assert.equal(isInsideRoots(path.resolve('/work/repo-evil/pom.xml'), [root]), false, 'prefix match must respect path separators');
});

test('URL policy: only https (http only for localhost); only http(s) links are ever opened', () => {
  assert.equal(isAllowedUrl('https://registry.npmjs.org'), true);
  assert.equal(isAllowedUrl('http://localhost:4873'), true);
  assert.equal(isAllowedUrl('http://127.0.0.1:8081/repo'), true);
  for (const bad of ['http://registry.npmjs.org', 'http://localhost.evil.com', 'file:///etc/passwd', 'ftp://x', 'javascript:alert(1)', 'not a url']) assert.equal(isAllowedUrl(bad), false, bad);
  assert.equal(safeExternalUrl('https://github.com/advisories/GHSA-x'), 'https://github.com/advisories/GHSA-x');
  for (const bad of ['javascript:alert(1)', 'command:workbench.action.terminal.new', 'vscode://x', 'file:///c:/x', 'data:text/html,x']) assert.equal(safeExternalUrl(bad), undefined, bad);
});

test('Markdown export neutralises HTML and hostile links from advisory data', () => {
  const results: FileResult[] = [
    {
      file: path.join(os.tmpdir(), 'package-lock.json'),
      ecosystem: 'npm',
      packageCount: 1,
      scannedAt: '',
      warnings: [],
      findings: [
        {
          ecosystem: 'npm', name: '<img src=x onerror=alert(1)>', version: '1.0.0', key: 'x@1.0.0', direct: true, dev: false, via: [], signals: [], riskScore: 0, suspicious: false, maxSeverity: 'high',
          vulns: [{ id: 'GHSA-evil', aliases: [], summary: 'x', severity: 'high', fixedVersions: [], references: [], url: 'javascript:alert(document.cookie)', isMalicious: false }],
        },
      ],
    },
  ];
  const md = toMarkdown(results, os.tmpdir());
  assert.ok(!md.includes('<img'), 'raw HTML must be escaped');
  assert.ok(!md.includes('javascript:'), 'non-http links must not be emitted');
  assert.match(md, /\| GHSA-evil \|/);
});

test('Manifest reader refuses oversized files and non-files', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ds-sec-'));
  try {
    const big = path.join(dir, 'package-lock.json');
    await fs.writeFile(big, 'x'.repeat(4096));
    let reason = '';
    assert.equal(await readTextFile(big, (r) => (reason = r), 1024), undefined);
    assert.match(reason, /exceeds/);
    assert.equal(await readTextFile(dir), undefined, 'directories are not read');
    assert.equal(await readTextFile(big, undefined, 1 << 20), 'x'.repeat(4096));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// ---- hostile HTTP server (localhost is the only place plain HTTP is allowed) ----
let server: http.Server;
let base = '';
let hits: string[] = [];
before(async () => {
  server = http.createServer((req, res) => {
    hits.push(req.url ?? '');
    if (req.url === '/huge') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ pad: 'x'.repeat(10_000) }));
    } else if (req.url === '/huge-declared') {
      res.writeHead(200, { 'content-length': String(10 * 1024 * 1024 * 1024) });
      res.end();
    } else if (req.url === '/redirect-downgrade') {
      res.writeHead(302, { location: 'http://192.0.2.1/stolen' }); // TEST-NET: must never be contacted
      res.end();
    } else if (req.url === '/redirect-ok') {
      res.writeHead(302, { location: '/ok' });
      res.end();
    } else if (req.url === '/loop') {
      res.writeHead(302, { location: '/loop' });
      res.end();
    } else {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    }
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => new Promise<void>((r) => server.close(() => r())));

test('HTTP: response size cap (streamed and declared), safe redirects only', async () => {
  const client = new Http(1024);
  await assert.rejects(client.json(`${base}/huge`, { retries: 0 }), /exceeded 1024 bytes/);
  await assert.rejects(client.json(`${base}/huge-declared`, { retries: 0 }), /too large/);
  assert.deepEqual(await client.json(`${base}/redirect-ok`, { retries: 0 }), { ok: true });
  hits = [];
  const t = Date.now();
  await assert.rejects(client.json(`${base}/redirect-downgrade`, { retries: 2 }), /Refusing redirect/);
  assert.ok(Date.now() - t < 2000, 'refused redirects must not be retried or followed');
  assert.deepEqual(hits, ['/redirect-downgrade'], 'only the first hop may be requested');
  await assert.rejects(client.json(`${base}/loop`, { retries: 0 }), /too many redirects/);
  await assert.rejects(client.json('http://example.com/', { retries: 0 }), /Refusing non-HTTPS/);
});
