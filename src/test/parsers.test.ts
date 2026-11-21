import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as path from 'path';
import { cvss3Score } from '../core/cvss';
import { computePaths } from '../core/graph';
import { locatePackage } from '../core/locate';
import { parseCargoLock, parseComposerLock, parseGemfileLock, parseGoMod, parseNugetLock } from '../core/parsers/misc';
import { parsePackageLock } from '../core/parsers/npm';
import { parsePnpmLock } from '../core/parsers/pnpm';
import { parsePoetryOrUvLock, parseRequirements } from '../core/parsers/python';
import { parseYarnLock } from '../core/parsers/yarn';
import { parseGradleBuild } from '../core/parsers/gradle';
import { selectScanTargets } from '../core/parsers';
import { interpolate, parsePom, pickVersion } from '../core/resolvers/maven';
import { isTyposquat } from '../core/popular';
import { parseToml } from '../core/toml';
import { offlineSignals } from '../core/supplyChain';
import { MemoryCache } from '../core/cache';
import { Http } from '../core/http';
import type { CoreContext } from '../core/types';

const pkgJson = JSON.stringify({ dependencies: { express: '^4.17.0' }, devDependencies: { jest: '^29.0.0' } });

test('package-lock v3: nodes, nested resolution, roots, paths', () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { express: '^4.17.0' }, devDependencies: { jest: '^29.0.0' } },
      'node_modules/express': { version: '4.17.1', resolved: 'https://registry.npmjs.org/express/-/express-4.17.1.tgz', integrity: 'sha512-x', dependencies: { qs: '6.7.0', 'body-parser': '1.19.0' } },
      'node_modules/body-parser': { version: '1.19.0', integrity: 'sha512-y', resolved: 'https://registry.npmjs.org/b', dependencies: { qs: '6.7.0' } },
      'node_modules/qs': { version: '6.9.0', integrity: 'sha512-z', resolved: 'https://registry.npmjs.org/q' },
      'node_modules/express/node_modules/qs': { version: '6.7.0', integrity: 'sha512-w', resolved: 'https://registry.npmjs.org/q2' },
      'node_modules/jest': { version: '29.0.0', dev: true, integrity: 'sha512-j', resolved: 'https://registry.npmjs.org/j', hasInstallScript: true },
    },
  };
  const g = parsePackageLock('/p/package-lock.json', JSON.stringify(lock), pkgJson, true);
  assert.equal(g.nodes.size, 5);
  assert.deepEqual(g.nodes.get('express@4.17.1')!.deps.sort(), ['body-parser@1.19.0', 'qs@6.7.0']);
  assert.deepEqual(g.nodes.get('body-parser@1.19.0')!.deps, ['qs@6.9.0']); // hoisted copy
  assert.deepEqual(g.roots.sort(), ['express@4.17.1', 'jest@29.0.0']);
  assert.equal(g.nodes.get('jest@29.0.0')!.hasInstallScript, true);
  const paths = computePaths(g);
  assert.deepEqual(paths.get('qs@6.9.0')!.via, ['express@4.17.1', 'body-parser@1.19.0']);
  assert.equal(paths.get('express@4.17.1')!.direct, true);

  const noDev = parsePackageLock('/p/package-lock.json', JSON.stringify(lock), pkgJson, false);
  assert.ok(!noDev.nodes.has('jest@29.0.0'));
});

test('package-lock v1', () => {
  const lock = {
    lockfileVersion: 1,
    dependencies: {
      express: { version: '4.17.1', requires: { qs: '6.7.0' }, dependencies: { qs: { version: '6.7.0' } } },
      qs: { version: '6.9.0' },
      jest: { version: '29.0.0', dev: true },
    },
  };
  const g = parsePackageLock('/p/package-lock.json', JSON.stringify(lock), pkgJson, true);
  assert.deepEqual(g.nodes.get('express@4.17.1')!.deps, ['qs@6.7.0']);
  assert.deepEqual(g.roots.sort(), ['express@4.17.1', 'jest@29.0.0']);
});

test('yarn.lock v1', () => {
  const text = `# yarn lockfile v1

express@^4.17.0:
  version "4.17.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz#abc"
  integrity sha512-abc
  dependencies:
    qs "6.7.0"

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.2.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.2.0.tgz"

qs@6.7.0:
  version "6.7.0"
  resolved "https://evil.example.com/qs-6.7.0.tgz"
`;
  const g = parseYarnLock('/p/yarn.lock', text, pkgJson, true);
  assert.ok(g.nodes.has('@babel/core@7.2.0'));
  assert.deepEqual(g.nodes.get('express@4.17.1')!.deps, ['qs@6.7.0']);
  assert.deepEqual(g.roots, ['express@4.17.1']);
});

test('yarn berry', () => {
  const text = `__metadata:
  version: 6

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    lodash: ^4.17.0
  languageName: unknown
  linkType: soft

"lodash@npm:^4.17.0":
  version: 4.17.20
  resolution: "lodash@npm:4.17.20"
  checksum: abc
  languageName: node
  linkType: hard
`;
  const g = parseYarnLock('/p/yarn.lock', text, undefined, true);
  assert.deepEqual(g.roots, ['lodash@4.17.20']);
});

test('pnpm v9 and v6', () => {
  const v9 = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      express:
        specifier: ^4.17.0
        version: 4.17.1
packages:
  express@4.17.1:
    resolution: {integrity: sha512-a}
  qs@6.7.0:
    resolution: {integrity: sha512-b}
snapshots:
  express@4.17.1:
    dependencies:
      qs: 6.7.0
  qs@6.7.0: {}
`;
  const g = parsePnpmLock('/p/pnpm-lock.yaml', v9, true);
  assert.deepEqual(g.roots, ['express@4.17.1']);
  assert.deepEqual(g.nodes.get('express@4.17.1')!.deps, ['qs@6.7.0']);

  const v6 = `lockfileVersion: '6.0'
dependencies:
  '@scope/a':
    specifier: ^1.0.0
    version: 1.0.0(react@18.2.0)
packages:
  /@scope/a@1.0.0(react@18.2.0):
    resolution: {integrity: sha512-a}
    dependencies:
      react: 18.2.0
  /react@18.2.0:
    resolution: {integrity: sha512-r}
`;
  const g6 = parsePnpmLock('/p/pnpm-lock.yaml', v6, true);
  assert.deepEqual(g6.roots, ['@scope/a@1.0.0']);
  assert.deepEqual(g6.nodes.get('@scope/a@1.0.0')!.deps, ['react@18.2.0']);
});

test('requirements.txt with pip-compile via comments', () => {
  const text = `flask==2.0.1
    # via -r requirements.in
werkzeug==2.0.0
    # via flask
requests>=2.0
Django[bcrypt]==3.2.1 ; python_version > "3.6"
`;
  const g = parseRequirements('/p/requirements.txt', text);
  assert.ok(g.nodes.has('django@3.2.1'));
  assert.deepEqual(g.nodes.get('flask@2.0.1')!.deps, ['werkzeug@2.0.0']);
  assert.ok(g.warnings.some((w) => w.includes('requests')));
});

test('uv.lock', () => {
  const text = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "httpx" },
]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
]

[[package]]
name = "idna"
version = "3.7"
source = { registry = "https://pypi.org/simple" }
`;
  const g = parsePoetryOrUvLock('/p/uv.lock', text, undefined, true);
  assert.deepEqual(g.roots, ['httpx@0.27.0']);
  assert.deepEqual(g.nodes.get('httpx@0.27.0')!.deps, ['idna@3.7']);
});

test('go.mod', () => {
  const g = parseGoMod('/p/go.mod', `module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.10.0 // indirect\n)\n`);
  assert.deepEqual(g.roots, ['github.com/gin-gonic/gin@1.9.0']);
  assert.ok(g.nodes.has('golang.org/x/net@0.10.0'));
});

test('Cargo.lock', () => {
  const text = `version = 3
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
`;
  const g = parseCargoLock('/p/Cargo.lock', text);
  assert.deepEqual(g.roots, ['serde@1.0.100']);
});

test('Gemfile.lock', () => {
  const text = `GEM
  remote: https://rubygems.org/
  specs:
    rails (6.0.0)
      rack (>= 2.0)
    rack (2.0.1)
    nokogiri (1.13.0-x86_64-linux)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 6.0)
  nokogiri
`;
  const g = parseGemfileLock('/p/Gemfile.lock', text);
  assert.deepEqual(g.roots.sort(), ['nokogiri@1.13.0', 'rails@6.0.0']);
  assert.deepEqual(g.nodes.get('rails@6.0.0')!.deps, ['rack@2.0.1']);
});

test('composer.lock and NuGet lock', () => {
  const c = parseComposerLock('/p/composer.lock', JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: 'v7.0.0', require: { 'psr/http': '^1' } }, { name: 'psr/http', version: '1.0.0' }] }), JSON.stringify({ require: { 'guzzlehttp/guzzle': '^7' } }), true);
  assert.deepEqual(c.roots, ['guzzlehttp/guzzle@7.0.0']);
  const n = parseNugetLock('/p/packages.lock.json', JSON.stringify({ version: 1, dependencies: { 'net8.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.1' }, 'System.X': { type: 'Transitive', resolved: '4.0.0' } } } }));
  assert.deepEqual(n.roots, ['Newtonsoft.Json@12.0.1']);
});

test('pom parsing & interpolation', () => {
  const pom = parsePom(`<project><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.5.0</version></parent>
  <artifactId>demo</artifactId><properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>\${log4j.version}</version>
  <exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions></dependency></dependencies></project>`);
  assert.equal(pom.parent?.version, '2.5.0');
  assert.equal(pom.deps[0].version, '${log4j.version}');
  assert.deepEqual(pom.deps[0].exclusions, ['x:y']);
  assert.equal(interpolate(pom.deps[0].version, pom.properties), '2.14.1');
  assert.equal(pickVersion('[1.2,2.0)'), '1.2');
  assert.equal(pickVersion('[1.5.0]'), '1.5.0');
});

test('gradle build parsing', () => {
  const { decls, bootVersion } = parseGradleBuild(`plugins { id 'org.springframework.boot' version '3.1.0' }
def jacksonVersion = '2.13.0'
dependencies {
  implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
  implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
  implementation 'org.springframework.boot:spring-boot-starter-web'
  testImplementation group: 'junit', name: 'junit', version: '4.12'
  implementation platform('com.amazonaws:aws-java-sdk-bom:1.12.0')
}`);
  assert.equal(bootVersion, '3.1.0');
  const find = (a: string) => decls.find((d) => d.artifactId === a)!;
  assert.equal(find('log4j-core').version, '2.14.1');
  assert.equal(find('jackson-databind').version, '2.13.0');
  assert.equal(find('spring-boot-starter-web').version, undefined);
  assert.equal(find('junit').dev, true);
  assert.equal(find('aws-java-sdk-bom').platform, true);
});

test('CVSS v3 scoring', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'), 5.9);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'), 5.5);
});

test('TOML parser', () => {
  const t = parseToml(`[versions]\nkotlin = "1.9.0"\n[libraries]\nfoo = { module = "a:b", version.ref = "kotlin" }\n'quoted key' = 'lit'\narr = [\n  "x", # c\n  "y",\n]\n`);
  assert.equal((t.versions as Record<string, string>).kotlin, '1.9.0');
  const foo = (t.libraries as Record<string, Record<string, unknown>>).foo;
  assert.equal(foo.module, 'a:b');
  assert.deepEqual((foo.version as Record<string, string>).ref, 'kotlin');
  assert.deepEqual((t.libraries as Record<string, unknown>).arr, ['x', 'y']);
});

test('typosquat detection', () => {
  assert.equal(isTyposquat('npm', 'expres'), 'express');
  assert.equal(isTyposquat('npm', 'crossenv'), 'cross-env');
  assert.equal(isTyposquat('npm', 'lodahs'), 'lodash');
  assert.equal(isTyposquat('PyPI', 'reqeusts'), 'requests');
  assert.equal(isTyposquat('npm', 'express'), undefined);
  assert.equal(isTyposquat('npm', 'preact'), undefined);
  assert.equal(isTyposquat('npm', 'left-pad'), undefined);
});

test('offline supply-chain signals', () => {
  const ctx = { config: { supplyChain: { allowedRegistries: ['registry.npmjs.org'] } } } as unknown as CoreContext;
  const s = offlineSignals({ ecosystem: 'npm', name: 'qs', version: '1.0.0', direct: false, node: { key: 'qs@1.0.0', name: 'qs', version: '1.0.0', deps: [], resolved: 'http://evil.example.com/qs.tgz', source: 'registry' } }, ctx);
  const codes = s.map((x) => x.code);
  assert.ok(codes.includes('untrusted-registry'));
  assert.ok(codes.includes('insecure-transport'));
  assert.ok(codes.includes('missing-integrity'));
});

test('scan target selection', () => {
  const r = path.resolve('/r');
  const t = selectScanTargets([
    path.join(r, 'package.json'),
    path.join(r, 'package-lock.json'),
    path.join(r, 'packages/a/package.json'),
    path.join(r, 'svc/pom.xml'),
    path.join(r, 'py/requirements.txt'),
    path.join(r, 'py/requirements-dev.txt'),
    path.join(r, 'py2/poetry.lock'),
    path.join(r, 'py2/requirements.txt'),
  ]);
  assert.deepEqual(
    t.map((x) => path.relative(r, x).replace(/\\/g, '/')).sort(),
    ['package-lock.json', 'py/requirements-dev.txt', 'py/requirements.txt', 'py2/poetry.lock', 'svc/pom.xml'],
  );
});

test('locate package lines', () => {
  const text = '{\n  "dependencies": {\n    "express": "^4"\n  }\n}';
  assert.equal(locatePackage(text, '/p/package.json', 'express'), 2);
  const pom = '<project>\n<dependencies>\n<dependency>\n<groupId>g</groupId>\n<artifactId>log4j-core</artifactId>';
  assert.equal(locatePackage(pom, '/p/pom.xml', 'g:log4j-core'), 4);
});

// keep imports used
void MemoryCache;
void Http;
