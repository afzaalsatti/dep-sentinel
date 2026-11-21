import assert from 'node:assert/strict';
import { test } from 'node:test';
import { applyEdits } from 'jsonc-parser';
import { OffsetEdit, planMavenPin, planNpmOverride } from '../core/overrides';
import { parsePom } from '../core/resolvers/maven';

const apply = (text: string, edits: OffsetEdit[]) => applyEdits(text, edits);

test('npm override uses a version selector and keeps 2-space formatting', () => {
  const pkg = '{\n  "name": "web",\n  "dependencies": {\n    "express": "4.17.1"\n  }\n}\n';
  const plan = planNpmOverride(pkg, '/p/package-lock.json', 'qs', '6.7.0', '6.7.3')!;
  const out = apply(pkg, plan.edits);
  assert.deepEqual(JSON.parse(out).overrides, { 'qs@6.7.0': '6.7.3' });
  assert.match(out, /\n {2}"overrides": \{\n {4}"qs@6\.7\.0": "6\.7\.3"\n {2}\}/);
  assert.equal(plan.description, 'overrides["qs@6.7.0"] = "6.7.3"');
});

test('npm override merges into an existing overrides object, 4-space indent', () => {
  const pkg = '{\n    "overrides": {\n        "semver": "7.5.4"\n    }\n}';
  const out = apply(pkg, planNpmOverride(pkg, '/p/package-lock.json', 'qs', '6.7.0', '6.7.3')!.edits);
  assert.deepEqual(JSON.parse(out).overrides, { semver: '7.5.4', 'qs@6.7.0': '6.7.3' });
  assert.match(out, /\n {8}"qs@6\.7\.0"/);
});

test('pnpm and yarn use their own keys; existing hand-written overrides are respected', () => {
  const pkg = '{\n  "name": "x"\n}';
  assert.deepEqual(JSON.parse(apply(pkg, planNpmOverride(pkg, '/p/pnpm-lock.yaml', 'qs', '6.7.0', '6.7.3')!.edits)).pnpm, { overrides: { 'qs@6.7.0': '6.7.3' } });
  assert.deepEqual(JSON.parse(apply(pkg, planNpmOverride(pkg, '/p/yarn.lock', 'qs', '6.7.0', '6.7.3')!.edits)).resolutions, { qs: '6.7.3' });
  assert.equal(planNpmOverride('{"overrides":{"qs":"6.5.0"}}', '/p/package-lock.json', 'qs', '6.7.0', '6.7.3'), undefined);
});

test('maven pin creates <dependencyManagement> before <dependencies> and is understood by the resolver', () => {
  const pom = '<project>\n  <artifactId>a</artifactId>\n  <dependencies>\n    <dependency>\n      <groupId>x</groupId>\n      <artifactId>y</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n';
  const plan = planMavenPin(pom, 'org.apache.tomcat.embed:tomcat-embed-core', '9.0.98')!;
  const out = apply(pom, plan.edits);
  assert.match(out, /\n {2}<dependencyManagement>\n {4}<dependencies>\n {6}<dependency>\n {8}<groupId>org\.apache\.tomcat\.embed<\/groupId>/);
  assert.ok(out.indexOf('<dependencyManagement>') < out.indexOf('<dependencies>\n    <dependency>\n      <groupId>x'));
  const parsed = parsePom(out);
  assert.deepEqual(parsed.managed.map((d) => [d.groupId, d.artifactId, d.version]), [['org.apache.tomcat.embed', 'tomcat-embed-core', '9.0.98']]);
  assert.equal(parsed.deps.length, 1);
});

test('maven pin appends to an existing <dependencyManagement>, skips already-managed artifacts', () => {
  const pom = '<project>\n\t<dependencyManagement>\n\t\t<dependencies>\n\t\t\t<dependency><groupId>g</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency>\n\t\t</dependencies>\n\t</dependencyManagement>\n</project>';
  const out = apply(pom, planMavenPin(pom, 'a.b:c', '2.0')!.edits);
  assert.deepEqual(parsePom(out).managed.map((d) => `${d.groupId}:${d.artifactId}:${d.version}`), ['a.b:c:2.0', 'g:bom:1']);
  assert.match(out, /\n\t\t\t<dependency>\n\t\t\t\t<groupId>a\.b<\/groupId>/);
  assert.equal(planMavenPin(out, 'a.b:c', '3.0'), undefined);
});
