import assert from 'node:assert/strict';
import { test } from 'node:test';
import { computeVersionEdit } from '../core/bump';
import type { Vulnerability } from '../core/types';
import { compareVersions, describeFixText, recommendFix } from '../core/versions';

const vuln = (id: string, fixed: string[]): Vulnerability => ({ id, aliases: [], summary: '', severity: 'high', fixedVersions: fixed, references: [], url: '', isMalicious: false });

test('compareVersions across ecosystems', () => {
  const lt = (a: string, b: string) => assert.equal(compareVersions(a, b), -1, `${a} < ${b}`);
  lt('1.2.0', '1.10.0');
  lt('1.0.0-beta.1', '1.0.0');
  lt('1.0.0-alpha', '1.0.0-beta');
  lt('1.0.0-rc.1', '1.0.0');
  lt('2.14.1', '2.16.0');
  lt('5.2.20.RELEASE', '5.3.7');
  lt('v0.9.0', 'v0.10.0');
  lt('1.0', '1.0.1');
  assert.equal(compareVersions('1.0', '1.0.0'), 0);
  assert.equal(compareVersions('5.3.18', '5.3.18.RELEASE'), 0);
  assert.equal(compareVersions('2.0.0.Final', '2.0.0'), 0);
});

test('recommendFix picks the nearest fix on the same line and the max across advisories', () => {
  // log4j 2.14.1: fixes listed for several branches
  const r = recommendFix('2.14.1', [vuln('A', ['2.15.0', '2.3.1', '2.12.2']), vuln('B', ['2.16.0', '2.12.2', '2.3.1']), vuln('C', ['2.17.1', '2.12.4', '2.3.2'])]);
  assert.equal(r.version, '2.17.1');
  assert.deepEqual(r.unfixed, []);
  // Spring 5.3.7 must not be "fixed" by a 5.2.x backport
  assert.equal(recommendFix('5.3.7', [vuln('S', ['5.2.20.RELEASE', '5.3.18'])]).version, '5.3.18');
  const partial = recommendFix('1.0.0', [vuln('X', ['1.2.0']), vuln('Y', [])]);
  assert.equal(partial.version, '1.2.0');
  assert.deepEqual(partial.unfixed, ['Y']);
});

test('recommendFix separates same-major upgrade from a major upgrade', () => {
  // Spring 5.3.7: most advisories fixed on 5.3.x, one only fixed on 6.x
  const r = recommendFix('5.3.7', [vuln('A', ['5.2.20.RELEASE', '5.3.18']), vuln('B', ['5.3.33', '6.0.18']), vuln('C', ['6.1.14'])]);
  assert.equal(r.version, '6.1.14');
  assert.equal(r.safeVersion, '5.3.33');
  assert.equal(r.safeFixCount, 2);
  // Nothing on the current line
  const none = recommendFix('3.2.1', [vuln('D', ['4.2.26', '5.1.14'])]);
  assert.equal(none.version, '4.2.26');
  assert.equal(none.safeVersion, undefined);
  // 0.x: minor is the breaking line
  assert.equal(recommendFix('0.21.1', [vuln('E', ['0.21.2', '0.22.0'])]).safeVersion, '0.21.2');
  assert.equal(recommendFix('0.21.1', [vuln('F', ['0.22.0'])]).safeVersion, undefined);
});

test('recommendFix ignores fixed versions that were never publicly released', () => {
  // Spring 5.3.42 is a commercial-only release – not on Maven Central.
  const published = new Set(['5.3.7', '5.3.18', '5.3.39', '6.0.18', '6.1.14']);
  const r = recommendFix('5.3.7', [vuln('A', ['5.3.18']), vuln('B', ['5.3.42', '6.1.14'])], published);
  assert.equal(r.safeVersion, '5.3.18');
  assert.equal(r.safeFixCount, 1);
  assert.equal(r.version, '6.1.14');
  // Go versions are published with a "v" prefix
  assert.equal(recommendFix('1.6.0', [vuln('G', ['1.9.1'])], new Set(['1.9.1'])).version, '1.9.1');
});

test('describeFixText wording', () => {
  const base = { ecosystem: 'npm' as const, name: 'x', version: '1.0.0', key: 'x@1.0.0', dev: false, via: [], signals: [], riskScore: 0, suspicious: false, maxSeverity: 'high' as const, unfixed: [] };
  assert.equal(describeFixText({ ...base, direct: true, vulns: [vuln('A', ['1.0.1'])], fixVersion: '1.0.1', safeFixVersion: '1.0.1', safeFixCount: 1 }), 'Upgrade to 1.0.1.');
  assert.equal(
    describeFixText({ ...base, direct: true, vulns: [vuln('A', ['1.0.1']), vuln('B', ['2.0.0'])], fixVersion: '2.0.0', safeFixVersion: '1.0.1', safeFixCount: 1 }),
    'Upgrade to 1.0.1 – same major, fixes 1 of 2; 2.0.0 fixes all (major upgrade).',
  );
  assert.match(describeFixText({ ...base, direct: false, vulns: [vuln('B', ['2.0.0'])], fixVersion: '2.0.0', safeFixCount: 0 }), /^Only fixed in 2\.0\.0 \(major upgrade of a transitive dependency/);
});

test('computeVersionEdit: package.json keeps the range operator', () => {
  const text = '{\n  "dependencies": {\n    "minimist": "^1.2.0",\n    "lodash": "4.17.15"\n  }\n}';
  const e = computeVersionEdit(text, '/p/package.json', 'minimist', 2, '1.2.6')!;
  const line = text.split('\n')[2];
  assert.equal(line.slice(0, e.start) + e.newText + line.slice(e.end), '    "minimist": "^1.2.6",');
  assert.equal(computeVersionEdit('{"x": "git+https://github.com/a/b"}', '/p/package.json', 'x', 0, '1.0.0'), undefined);
});

test('computeVersionEdit: requirements, go.mod, gradle', () => {
  const apply = (text: string, file: string, name: string, line: number, target: string) => {
    const e = computeVersionEdit(text, file, name, line, target)!;
    const l = text.split('\n')[e.line];
    return l.slice(0, e.start) + e.newText + l.slice(e.end);
  };
  assert.equal(apply('Django[bcrypt]==3.2.1 ; python_version > "3.6"', '/p/requirements.txt', 'django', 0, '3.2.25'), 'Django[bcrypt]==3.2.25 ; python_version > "3.6"');
  assert.equal(apply('require (\n\tgithub.com/gin-gonic/gin v1.6.0\n)', '/p/go.mod', 'github.com/gin-gonic/gin', 1, '1.9.1'), '\tgithub.com/gin-gonic/gin v1.9.1');
  assert.equal(apply("  implementation 'org.apache.logging.log4j:log4j-core:2.14.1'", '/p/build.gradle', 'org.apache.logging.log4j:log4j-core', 0, '2.17.1'), "  implementation 'org.apache.logging.log4j:log4j-core:2.17.1'");
  assert.equal(computeVersionEdit('implementation "g:a:$ver"', '/p/build.gradle', 'g:a', 0, '2.0'), undefined);
});

test('computeVersionEdit: pom.xml literal, property and managed versions', () => {
  const pom = [
    '<project>', //0
    '  <properties>', //1
    '    <jackson.version>2.9.8</jackson.version>', //2
    '  </properties>', //3
    '  <dependencies>', //4
    '    <dependency>', //5
    '      <groupId>org.apache.logging.log4j</groupId>', //6
    '      <artifactId>log4j-core</artifactId>', //7
    '      <version>2.14.1</version>', //8
    '    </dependency>', //9
    '    <dependency>', //10
    '      <groupId>com.fasterxml.jackson.core</groupId>', //11
    '      <artifactId>jackson-databind</artifactId>', //12
    '      <version>${jackson.version}</version>', //13
    '    </dependency>', //14
    '    <dependency>', //15
    '      <groupId>org.springframework.boot</groupId>', //16
    '      <artifactId>spring-boot-starter-web</artifactId>', //17
    '    </dependency>', //18
    '  </dependencies>', //19
    '</project>',
  ].join('\n');
  const log4j = computeVersionEdit(pom, '/p/pom.xml', 'org.apache.logging.log4j:log4j-core', 7, '2.17.1')!;
  assert.equal(log4j.line, 8);
  assert.equal(pom.split('\n')[8].slice(log4j.start, log4j.end), '2.14.1');
  const jackson = computeVersionEdit(pom, '/p/pom.xml', 'com.fasterxml.jackson.core:jackson-databind', 12, '2.12.7')!;
  assert.equal(jackson.line, 2, 'should edit the property definition');
  assert.equal(pom.split('\n')[2].slice(jackson.start, jackson.end), '2.9.8');
  assert.equal(computeVersionEdit(pom, '/p/pom.xml', 'org.springframework.boot:spring-boot-starter-web', 17, '2.7.0'), undefined, 'managed version must not be edited');
});
