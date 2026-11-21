import assert from 'node:assert/strict';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { DepSentinelApi } from '../../extension';
import type { Node } from '../../tree';

type TestFn = () => Promise<void>;
const tests: [string, TestFn][] = [];
const test = (name: string, fn: TestFn) => tests.push([name, fn]);

async function waitFor<T>(what: string, fn: () => T | undefined | false | Promise<T | undefined | false>, timeoutMs = 90_000): Promise<T> {
  const start = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - start > timeoutMs) throw new Error(`Timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

const ws = () => vscode.workspace.workspaceFolders![0].uri.fsPath;
const diags = (rel: string) => vscode.languages.getDiagnostics(vscode.Uri.file(path.join(ws(), rel)));
const codeOf = (d: vscode.Diagnostic) => (typeof d.code === 'object' ? String(d.code.value) : String(d.code ?? ''));

let api: DepSentinelApi;

test('extension activates and registers commands', async () => {
  const ext = vscode.extensions.getExtension<DepSentinelApi>('afzaalshoukat.dep-sentinel');
  assert.ok(ext, 'extension not found');
  api = await ext.activate();
  const cmds = await vscode.commands.getCommands(true);
  for (const c of ['depSentinel.scanNow', 'depSentinel.showReport', 'depSentinel.ignoreAdvisory', 'depSentinel.trustPackage', 'depSentinel.clearCache']) {
    assert.ok(cmds.includes(c), `missing command ${c}`);
  }
  assert.equal(api.getResults().length, 0, 'scanOnStartup=false should mean no results yet');
});

test('manual scan discovers every manifest (lockfile preferred over package.json)', async () => {
  await vscode.commands.executeCommand('depSentinel.scanNow');
  const files = api.getResults().map((r) => path.relative(ws(), r.file).replace(/\\/g, '/')).sort();
  assert.deepEqual(files, ['api/pom.xml', 'ml/requirements.txt', 'web/package-lock.json']);
  for (const r of api.getResults()) assert.equal(r.error, undefined, `${r.file}: ${r.error}`);
});

test('npm: malicious transitive dep is reported on the direct dependency line in package.json', async () => {
  const d = diags('web/package.json');
  const text = await fs.readFile(path.join(ws(), 'web/package.json'), 'utf8');
  const lineOf = (s: string) => text.split('\n').findIndex((l) => l.includes(`"${s}"`));
  const flat = d.find((x) => x.message.includes('flatmap-stream@0.1.1'));
  assert.ok(flat, 'flatmap-stream diagnostic missing');
  assert.match(flat.message, /MALICIOUS/);
  assert.match(flat.message, /transitive via event-stream/);
  assert.equal(flat.range.start.line, lineOf('event-stream'));
  assert.equal(flat.severity, vscode.DiagnosticSeverity.Error);
});

test('npm: CVE with fix version and supply-chain SUSPICIOUS flag for untrusted registry', async () => {
  const d = diags('web/package.json');
  const cve = d.find((x) => codeOf(x) === 'GHSA-xvch-5gv4-984h');
  assert.ok(cve, 'minimist GHSA-xvch-5gv4-984h missing');
  assert.match(cve.message, /Upgrade to 1\.2\.6\./);
  assert.equal(cve.code && typeof cve.code === 'object' && cve.code.target.toString(), 'https://github.com/advisories/GHSA-xvch-5gv4-984h');
  const sus = d.find((x) => x.message.includes('SUSPICIOUS') && x.message.includes('minimist'));
  assert.ok(sus, 'minimist not flagged suspicious');
  assert.match(sus.message, /evil-mirror\.example\.com/);
  assert.ok(!d.some((x) => x.message.includes('lodash@4.18.1')), 'patched lodash must not be reported');
});

test('maven: direct log4j and transitive Spring/Tomcat vulns resolved from Maven Central', async () => {
  const d = diags('api/pom.xml');
  const log4shell = d.find((x) => codeOf(x) === 'GHSA-jfh8-c2jp-5v3q');
  assert.ok(log4shell, 'Log4Shell missing');
  assert.match(log4shell.message, /CVE-2021-44228/);
  const text = await fs.readFile(path.join(ws(), 'api/pom.xml'), 'utf8');
  assert.equal(log4shell.range.start.line, text.split('\n').findIndex((l) => l.includes('<artifactId>log4j-core</artifactId>')));
  const tomcat = d.find((x) => x.message.includes('tomcat-embed-core') && x.message.includes('transitive via org.springframework.boot:spring-boot-starter-web'));
  assert.ok(tomcat, 'transitive tomcat vuln missing');
  const pom = api.getResults().find((r) => r.file.endsWith('pom.xml'))!;
  assert.ok(pom.packageCount > 20, `expected full transitive tree, got ${pom.packageCount}`);
  // Real-world exploit data (live CISA KEV + FIRST EPSS): Log4Shell is a textbook known-exploited CVE.
  const log4j = pom.findings.find((f) => f.name.endsWith(':log4j-core'))!;
  const v = log4j.vulns.find((x) => x.id === 'GHSA-jfh8-c2jp-5v3q')!;
  assert.ok(v.kev, 'Log4Shell should be marked as exploited in the wild (CISA KEV)');
  assert.ok(v.epss && v.epss.score > 0.5, `Log4Shell should have a high EPSS score, got ${v.epss?.score}`);
  assert.match(log4shell.message, /exploited in the wild/);
});

test('python: requirements.txt vulnerabilities', async () => {
  const d = diags('ml/requirements.txt');
  assert.ok(d.some((x) => x.message.includes('django@3.2.1') && x.severity === vscode.DiagnosticSeverity.Error));
});

/** Package nodes below a project or file node (single-file projects list packages directly). */
const pkgsOf = (n: Node): Extract<Node, { kind: 'pkg' }>[] =>
  api.tree.getChildren(n).flatMap((c) => (c.kind === 'file' ? pkgsOf(c) : c.kind === 'pkg' ? [c] : []));
const projectOf = (suffix: string) =>
  api.tree.getChildren().find((n) => n.kind === 'project' && n.project.results.some((r) => r.file.endsWith(suffix))) as Extract<Node, { kind: 'project' }>;

test('tree view groups by project and exposes summary, packages, advisories', async () => {
  const roots = api.tree.getChildren();
  assert.equal(roots[0].kind, 'summary');
  const summary = api.tree.getTreeItem(roots[0]);
  assert.match(String(summary.label), /Last scan/);
  const projects = roots.filter((n): n is Extract<Node, { kind: 'project' }> => n.kind === 'project');
  assert.deepEqual(projects.map((p) => p.project.name).sort(), ['api', 'ml', 'web']);
  const web = projectOf('package-lock.json');
  assert.match(String(api.tree.getTreeItem(web).description), /npm · package-lock\.json/);
  const pkgs = pkgsOf(web);
  const flatNode = pkgs.find((n) => String(api.tree.getTreeItem(n).label) === 'flatmap-stream@0.1.1')!;
  assert.ok(flatNode);
  const item = api.tree.getTreeItem(flatNode);
  assert.equal(item.contextValue, 'pkg-suspicious');
  assert.match(String(item.description), /via event-stream@3\.3\.6/);
  const children = api.tree.getChildren(flatNode);
  assert.ok(children.some((c) => c.kind === 'vuln'));
  assert.ok(children.some((c) => c.kind === 'signal' && c.signal.code === 'known-malicious'));
  assert.ok(children.some((c) => c.kind === 'text' && /Path: event-stream@3\.3\.6 › flatmap-stream@0\.1\.1/.test(c.text)));
});

test('report and reveal commands run', async () => {
  await vscode.commands.executeCommand('depSentinel.showReport');
  const pkg = pkgsOf(projectOf('package-lock.json')).find((n) => n.finding.name === 'minimist')!;
  await vscode.commands.executeCommand('depSentinel.revealInFile', pkg);
  const editor = vscode.window.activeTextEditor!;
  assert.ok(editor.document.fileName.endsWith('package.json'));
  assert.match(editor.document.lineAt(editor.selection.start.line).text, /"minimist"/);
});

async function codeActionsAt(rel: string, line: number): Promise<vscode.CodeAction[]> {
  const uri = vscode.Uri.file(path.join(ws(), rel));
  const doc = await vscode.workspace.openTextDocument(uri);
  return (await vscode.commands.executeCommand<vscode.CodeAction[]>('vscode.executeCodeActionProvider', uri, doc.lineAt(line).range)) ?? [];
}

test('activity-bar badge shows the number of affected packages', async () => {
  const affected = api.getResults().flatMap((r) => r.findings).filter((f) => f.vulns.length || f.suspicious).length;
  assert.ok(affected > 0);
  assert.equal(api.badge()?.value, affected);
});

test('CodeLens summarises each affected dependency line', async () => {
  const uri = vscode.Uri.file(path.join(ws(), 'web/package.json'));
  const doc = await vscode.workspace.openTextDocument(uri);
  const lenses = (await vscode.commands.executeCommand<vscode.CodeLens[]>('vscode.executeCodeLensProvider', uri)) ?? [];
  const at = (needle: string) => lenses.find((l) => doc.lineAt(l.range.start.line).text.includes(needle))?.command;
  const minimist = at('"minimist"');
  assert.ok(minimist, `no lens on minimist; lenses: ${lenses.map((l) => l.command?.title).join(' | ')}`);
  assert.match(minimist.title, /2 vulnerabilities \(critical\) · fix → 1\.2\.6/);
  assert.match(minimist.title, /suspicious/);
  assert.equal(minimist.command, 'depSentinel.lineActions');
  assert.match(at('"event-stream"')!.title, /MALICIOUS package – remove it/);
  assert.equal(at('"lodash"'), undefined, 'clean dependency must not get a lens');
  // Tomcat etc. are shown on the line of the dependency that pulls them in
  const pomUri = vscode.Uri.file(path.join(ws(), 'api/pom.xml'));
  const pomDoc = await vscode.workspace.openTextDocument(pomUri);
  const pomLenses = (await vscode.commands.executeCommand<vscode.CodeLens[]>('vscode.executeCodeLensProvider', pomUri)) ?? [];
  const web = pomLenses.find((l) => pomDoc.lineAt(l.range.start.line).text.includes('spring-boot-starter-web'));
  assert.match(web?.command?.title ?? '', /\+ \d+ vulnerable sub-dependencies \(worst: critical\)/);
});

test('filter narrows the tree and shows the active filter', async () => {
  const pkgsShown = () =>
    api.tree.getChildren().filter((n) => n.kind === 'project' || n.kind === 'file').flatMap(pkgsOf);
  const all = pkgsShown().length;
  await vscode.commands.executeCommand('depSentinel.filter', 'supplyChain');
  const sc = pkgsShown();
  assert.ok(sc.length > 0 && sc.length < all, `supply-chain filter should narrow ${all} → ${sc.length}`);
  assert.ok(sc.every((n) => n.finding.suspicious || n.finding.vulns.some((v) => v.isMalicious) || n.finding.signals.some((s) => s.score >= 3)));
  await vscode.commands.executeCommand('depSentinel.filter', 'direct');
  assert.ok(pkgsShown().every((n) => n.finding.direct));
  await vscode.commands.executeCommand('depSentinel.filter', 'all');
  assert.equal(pkgsShown().length, all);
});

test('pause / resume monitoring updates state and status bar', async () => {
  await vscode.commands.executeCommand('depSentinel.pause');
  assert.equal(api.isPaused(), true);
  assert.match(api.statusText(), /paused/);
  assert.equal(api.tree.getChildren()[0].kind === 'summary' && (api.tree.getChildren()[0] as Extract<Node, { kind: 'summary' }>).state, 'paused');
  await vscode.commands.executeCommand('depSentinel.resume');
  assert.equal(api.isPaused(), false);
  assert.doesNotMatch(api.statusText(), /paused/);
});

test('export report writes Markdown, SARIF and JSON', async () => {
  const out = (ext: string) => vscode.Uri.file(path.join(ws(), `report.${ext}`));
  await vscode.commands.executeCommand('depSentinel.exportReport', 'markdown', out('md'));
  await vscode.commands.executeCommand('depSentinel.exportReport', 'sarif', out('sarif'));
  await vscode.commands.executeCommand('depSentinel.exportReport', 'json', out('json'));
  const md = await fs.readFile(out('md').fsPath, 'utf8');
  assert.match(md, /# Dependency security report/);
  assert.match(md, /☠ Malicious packages/);
  assert.match(md, /log4j-core/);
  const sarif = JSON.parse(await fs.readFile(out('sarif').fsPath, 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.some((r: { ruleId: string }) => r.ruleId === 'GHSA-jfh8-c2jp-5v3q'));
  assert.equal(JSON.parse(await fs.readFile(out('json').fsPath, 'utf8')).length, 3);
});

test('walkthrough is contributed and every step has its media', async () => {
  const ext = vscode.extensions.getExtension('afzaalshoukat.dep-sentinel')!;
  const wt = ext.packageJSON.contributes.walkthroughs[0];
  assert.equal(wt.id, 'depSentinel.gettingStarted');
  assert.equal(wt.steps.length, 6);
  for (const s of wt.steps) await fs.access(path.join(ext.extensionPath, s.media.markdown));
  const cmds = await vscode.commands.getCommands(true);
  for (const c of ['depSentinel.menu', 'depSentinel.gettingStarted', 'depSentinel.openSettings', 'depSentinel.exportReport', 'depSentinel.filter', 'depSentinel.lineActions']) {
    assert.ok(cmds.includes(c), `missing ${c}`);
  }
  // Opening the walkthrough must not throw
  await vscode.commands.executeCommand('depSentinel.gettingStarted');
});

test('quick fix upgrades a direct npm dependency in package.json (keeps formatting)', async () => {
  const rel = 'web/package.json';
  const text = await fs.readFile(path.join(ws(), rel), 'utf8');
  const line = text.split('\n').findIndex((l) => l.includes('"minimist"'));
  const finding = api.getResults().flatMap((r) => r.findings).find((f) => f.name === 'minimist')!;
  assert.ok(finding.fixVersion, 'minimist should have a fix version');
  const actions = await codeActionsAt(rel, line);
  const upgrade = actions.find((a) => a.title.startsWith(`Upgrade minimist to ${finding.fixVersion}`));
  assert.ok(upgrade, `no upgrade action; got: ${actions.map((a) => a.title).join(' | ')}`);
  assert.ok(upgrade.isPreferred);
  assert.ok(actions.some((a) => a.title === 'Open advisory GHSA-xvch-5gv4-984h'));
  assert.ok(actions.some((a) => a.title === 'Ignore GHSA-xvch-5gv4-984h in this workspace'));
  // Malicious packages must not get an "upgrade" – they must be removed.
  const esLine = text.split('\n').findIndex((l) => l.includes('"event-stream"'));
  assert.ok(!(await codeActionsAt(rel, esLine)).some((a) => a.title.startsWith('Upgrade')));

  assert.ok(await vscode.workspace.applyEdit(upgrade.edit!));
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(path.join(ws(), rel)));
  assert.equal(doc.lineAt(line).text, `    "minimist": "${finding.fixVersion}",`);
  await doc.save();
});

test('quick fix for pom.xml targets the <version> element', async () => {
  const rel = 'api/pom.xml';
  const text = await fs.readFile(path.join(ws(), rel), 'utf8');
  const lines = text.split('\n');
  const line = lines.findIndex((l) => l.includes('<artifactId>log4j-core</artifactId>'));
  const finding = api.getResults().flatMap((r) => r.findings).find((f) => f.name === 'org.apache.logging.log4j:log4j-core')!;
  const upgrade = (await codeActionsAt(rel, line)).find((a) => a.title.startsWith('Upgrade org.apache.logging.log4j:log4j-core'));
  assert.ok(upgrade, 'no pom upgrade action');
  const [[, edits]] = upgrade.edit!.entries();
  assert.equal(edits.length, 1);
  assert.equal(edits[0].newText, finding.fixVersion);
  assert.match(lines[edits[0].range.start.line], /<version>2\.14\.1<\/version>/);
  // Managed version (spring-boot-starter-web, from the parent) must not offer an edit.
  const webLine = lines.findIndex((l) => l.includes('<artifactId>spring-boot-starter-web</artifactId>'));
  assert.ok(!(await codeActionsAt(rel, webLine)).some((a) => a.title.startsWith('Upgrade org.springframework.boot:spring-boot-starter-web')));
});

test('quick fix pins a vulnerable transitive Maven dep via dependencyManagement and the re-scan honours it', async () => {
  const rel = 'api/pom.xml';
  const tomcat = () => api.getResults().find((r) => r.file.endsWith('pom.xml'))!.findings.find((f) => f.name === 'org.apache.tomcat.embed:tomcat-embed-core');
  const before = tomcat();
  assert.ok(before?.safeFixVersion, 'tomcat should have a same-major fix');
  const text = await fs.readFile(path.join(ws(), rel), 'utf8');
  const webLine = text.split('\n').findIndex((l) => l.includes('<artifactId>spring-boot-starter-web</artifactId>'));
  const actions = await codeActionsAt(rel, webLine);
  const pin = actions.find((a) => a.title.startsWith(`Force transitive org.apache.tomcat.embed:tomcat-embed-core ${before.version} → ${before.safeFixVersion} via dependencyManagement`));
  assert.ok(pin, `no pin action; got: ${actions.map((a) => a.title).join(' | ')}`);

  assert.ok(await vscode.workspace.applyEdit(pin.edit!));
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(path.join(ws(), rel)));
  assert.match(doc.getText(), new RegExp(`<dependencyManagement>[\\s\\S]*<artifactId>tomcat-embed-core</artifactId>\\s*<version>${before.safeFixVersion!.replace(/\./g, '\\.')}</version>[\\s\\S]*</dependencyManagement>`));
  await doc.save();
  // The file watcher re-scans pom.xml; the resolver applies the root's managed version to the transitive dep.
  await waitFor('tomcat finding to be resolved by the pin', () => !api.isScanning() && tomcat()?.version !== before.version);
  const after = tomcat();
  assert.ok(!after || after.vulns.length < before.vulns.length, `pin did not reduce tomcat advisories (${after?.version}: ${after?.vulns.length})`);
});

test('editing a manifest triggers an automatic re-scan', async () => {
  await fs.writeFile(path.join(ws(), 'ml/requirements.txt'), 'django==3.2.1\nflask==0.12\n');
  await waitFor('flask diagnostics after file change', () => diags('ml/requirements.txt').some((x) => x.message.includes('flask@0.12')));
});

test('ignoring an advisory via settings removes it after re-scan', async () => {
  await vscode.workspace.getConfiguration('depSentinel').update('ignoredAdvisories', ['GHSA-jfh8-c2jp-5v3q'], vscode.ConfigurationTarget.Workspace);
  await waitFor('Log4Shell to disappear', () => !api.isScanning() && !diags('api/pom.xml').some((x) => codeOf(x) === 'GHSA-jfh8-c2jp-5v3q') && diags('api/pom.xml').length > 0);
  // Suppression must never be invisible – and must be flagged when it comes from the repository's own settings.
  const note = api.tree.getChildren().find((n) => n.kind === 'text' && n.text.startsWith('Suppressed by settings')) as Extract<Node, { kind: 'text' }> | undefined;
  assert.ok(note, 'suppression notice missing from the tree');
  assert.match(note.text, /1 ignored advisory \(set by this workspace\)/);
  assert.equal(note.icon, 'warning');
  await vscode.workspace.getConfiguration('depSentinel').update('ignoredAdvisories', undefined, vscode.ConfigurationTarget.Workspace);
});

test('deleting a lockfile falls back to package.json registry resolution', async () => {
  await fs.rm(path.join(ws(), 'web/package-lock.json'));
  await waitFor('package.json becomes the scan target', () => !api.isScanning() && api.getResults().some((r) => r.file.endsWith(path.join('web', 'package.json'))));
  const r = api.getResults().find((x) => x.file.endsWith(path.join('web', 'package.json')))!;
  assert.ok(r.warnings.some((w) => w.includes('No lockfile')));
  assert.ok(!api.getResults().some((x) => x.file.endsWith('package-lock.json')), 'stale lockfile result should be removed');
});

export async function run(): Promise<void> {
  let failed = 0;
  for (const [name, fn] of tests) {
    const t = Date.now();
    try {
      await fn();
      console.log(`  ✔ ${name} (${Date.now() - t} ms)`);
    } catch (e) {
      failed++;
      console.log(`  ✘ ${name}\n      ${(e as Error).message.split('\n').join('\n      ')}`);
    }
  }
  console.log(`\n  ${tests.length - failed} passed, ${failed} failed`);
  if (failed) throw new Error(`${failed} integration test(s) failed`);
}
