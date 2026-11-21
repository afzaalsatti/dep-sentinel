import { randomBytes } from 'crypto';
import * as vscode from 'vscode';
import { describeFix, describeOrigin, findingLocation } from './diagnostics';
import { EPSS_LIKELY, pct } from './core/exploit';
import { safeExternalUrl } from './core/http';
import { FIX_LABEL, FIX_ORDER, priorityOf, PRIORITY_HINT, PRIORITY_LABEL, PRIORITY_ORDER, PriorityInfo } from './core/priority';
import { ECOSYSTEM_LABEL, groupProjects, Project, ProjectStats, statsOf } from './core/projects';
import type { FileResult, PackageFinding, Vulnerability } from './core/types';

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const nameOfKey = (key: string) => key.replace(/@[^@]*$/, '') || key;

let panel: vscode.WebviewPanel | undefined;
/** Findings referenced by index from the page. Messages may only point at these, never at arbitrary files or ids. */
let refs: { result: FileResult; finding: PackageFinding }[] = [];

export function showReport(results: FileResult[], lastScan: Date | undefined) {
  if (!panel) {
    panel = vscode.window.createWebviewPanel('depSentinel.report', 'DepSentinel Report', vscode.ViewColumn.Active, {
      // One nonce-locked inline script for sorting/filtering; no remote code, no command: links, no forms, no local files.
      enableScripts: true,
      enableCommandUris: false,
      enableForms: false,
      localResourceRoots: [],
    });
    panel.onDidDispose(() => (panel = undefined));
    panel.webview.onDidReceiveMessage((m: unknown) => void onMessage(m));
  }
  panel.webview.html = render(results, lastScan, panel.webview.cspSource);
  panel.reveal();
}

export function refreshReport(results: FileResult[], lastScan: Date | undefined) {
  if (panel) panel.webview.html = render(results, lastScan, panel.webview.cspSource);
}

export function workspaceRoots() {
  return (vscode.workspace.workspaceFolders ?? []).map((f) => ({ name: f.name, path: f.uri.fsPath }));
}

async function onMessage(m: unknown) {
  if (!m || typeof m !== 'object') return;
  const msg = m as { type?: unknown; ref?: unknown; id?: unknown };
  const ref = typeof msg.ref === 'number' && Number.isInteger(msg.ref) ? refs[msg.ref] : undefined;
  switch (msg.type) {
    case 'open': {
      if (!ref) return;
      const loc = await findingLocation(ref.result, ref.finding);
      const doc = await vscode.workspace.openTextDocument(loc.file);
      const range = doc.lineAt(Math.min(loc.line, doc.lineCount - 1)).range;
      await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside, preview: true, selection: range });
      return;
    }
    case 'ignore':
      if (ref && typeof msg.id === 'string' && ref.finding.vulns.some((v) => v.id === msg.id)) await vscode.commands.executeCommand('depSentinel.ignoreAdvisory', msg.id);
      return;
    case 'scan':
      await vscode.commands.executeCommand('depSentinel.scanNow');
      return;
    case 'export':
      await vscode.commands.executeCommand('depSentinel.exportReport');
      return;
  }
}

type Level = 'malicious' | 'critical' | 'high' | 'suspicious' | 'medium' | 'low';
const LEVELS: Level[] = ['malicious', 'critical', 'high', 'suspicious', 'medium', 'low'];
const LEVEL_LABEL: Record<Level, string> = { malicious: 'Malicious', critical: 'Critical', high: 'High', suspicious: 'Suspicious', medium: 'Medium', low: 'Low' };

function levelOf(f: PackageFinding): Level {
  if (f.vulns.some((v) => v.isMalicious)) return 'malicious';
  if (f.suspicious && f.maxSeverity !== 'critical') return 'suspicious';
  return f.maxSeverity === 'unknown' ? 'medium' : f.maxSeverity;
}

/** Colored count chips; zero counts are left out so the eye goes to what matters. */
function chips(s: ProjectStats, showClean = true): string {
  const parts: [number, string][] = [
    [s.malicious, 'malicious'],
    [s.critical, 'critical'],
    [s.high, 'high'],
    [s.suspicious, 'suspicious'],
    [s.medium, 'medium'],
    [s.low, 'low'],
  ];
  const html = parts
    .filter(([n]) => n > 0)
    .map(([n, cls]) => `<span class="chip ${cls}">${n} ${cls}</span>`)
    .join('');
  return html || (showClean ? '<span class="chip ok">✓ no issues</span>' : '');
}

function verdict(s: ProjectStats, projects: number, exploited: number): string {
  const kev = exploited
    ? ` <b>${plural(exploited, 'package has', 'packages have')} vulnerabilities attackers are exploiting right now</b> (CISA KEV); they are at the top of the list.`
    : '';
  if (s.malicious)
    return `<div class="banner bad"><span class="bicon">☠</span><div><b>${plural(s.malicious, 'malicious package')} found.</b> Remove ${s.malicious === 1 ? 'it' : 'them'} now and rotate any credentials (tokens, SSH keys, cloud keys) on machines where ${s.malicious === 1 ? 'it was' : 'they were'} installed.${kev}</div></div>`;
  if (exploited && !s.critical && !s.high)
    return `<div class="banner bad"><span class="bicon">!</span><div><b>Action needed:</b>${kev}</div></div>`;
  if (s.critical || s.high)
    return `<div class="banner bad"><span class="bicon">!</span><div><b>Action needed:</b> ${[s.critical && plural(s.critical, 'critical issue'), s.high && plural(s.high, 'high-severity issue')].filter(Boolean).join(' and ')}${
      s.suspicious ? `, plus ${plural(s.suspicious, 'suspicious package')}` : ''
    }. Start with the list below; each package says what to upgrade.${kev}</div></div>`;
  if (s.suspicious)
    return `<div class="banner warn"><span class="bicon">⚠</span><div><b>Review recommended:</b> ${plural(s.suspicious, 'package')} ${s.suspicious === 1 ? 'shows' : 'show'} signs of a supply-chain attack.</div></div>`;
  if (s.medium || s.low)
    return `<div class="banner warn"><span class="bicon">i</span><div><b>Low risk:</b> only ${plural(s.medium + s.low, 'medium or low-severity issue')}. Fix ${s.medium + s.low === 1 ? 'it' : 'them'} when convenient.</div></div>`;
  return `<div class="banner good"><span class="bicon">✓</span><div><b>All clear.</b> No known vulnerabilities or suspicious packages in ${plural(projects, 'project')}.</div></div>`;
}

function sevLabel(v: Vulnerability) {
  return v.isMalicious ? 'MALICIOUS' : v.severity === 'unknown' ? 'MEDIUM?' : v.severity.toUpperCase();
}

function advisory(v: Vulnerability): string {
  const id = v.aliases.find((a) => a.startsWith('CVE-')) ?? v.id;
  const url = safeExternalUrl(v.url);
  const fixed = v.fixedVersions.length ? `<span class="fixed">fixed in ${esc(v.fixedVersions.slice(0, 3).join(', '))}</span>` : '<span class="nofix">no fix yet</span>';
  const xb = [
    v.kev
      ? `<span class="xb kev" title="Listed in CISA's Known Exploited Vulnerabilities catalog since ${esc(v.kev.dateAdded)}${v.kev.ransomware ? '; used in ransomware campaigns' : ''}">🔥 Exploited${v.kev.ransomware ? ' · ransomware' : ''}</span>`
      : '',
    v.epss
      ? `<span class="xb epss${v.epss.score >= EPSS_LIKELY ? ' hot' : ''}" title="EPSS: ${pct(v.epss.score)} chance of exploitation in the next 30 days, higher than ${Math.floor(v.epss.percentile * 100)}% of CVEs">EPSS ${pct(v.epss.score)}</span>`
      : '',
  ].join('');
  const ignore = v.isMalicious ? '' : `<button class="ghost tiny ign" data-act="ignore" data-id="${esc(v.id)}" title="Ignore ${esc(v.id)} in this workspace (asks first)">Ignore</button>`;
  return `<li><span class="pill ${v.isMalicious ? 'malicious' : v.severity}">${sevLabel(v)}${v.cvssScore !== undefined ? ` ${v.cvssScore}` : ''}</span>${xb}
    <span class="advtext">${url ? `<a href="${esc(url)}">${esc(id)}</a>` : `<b>${esc(id)}</b>`} <span class="sum">${esc(v.summary || 'No summary provided')}</span> ${fixed}</span>${ignore}</li>`;
}

function todoText(f: PackageFinding): { text: string; cls: string } {
  if (f.vulns.some((v) => v.isMalicious)) return { text: `Remove ${f.name} immediately and rotate credentials.`, cls: 'bad' };
  if (!f.vulns.length) return { text: 'Check this release before trusting it, or pin the previous version.', cls: 'warn' };
  const text = describeFix(f).trim();
  return text ? { text, cls: '' } : { text: 'No fixed version is published yet. Consider replacing the package or check the advisory for a workaround.', cls: 'warn' };
}

interface Item {
  ref: number;
  f: PackageFinding;
  r: FileResult;
  p: Project;
  level: Level;
  prio: PriorityInfo;
}

function findingCard(it: Item, multiFile: boolean): string {
  const { f, r, p, level, prio } = it;
  const malicious = level === 'malicious';
  const root = f.direct ? f.name : f.introducedBy ? nameOfKey(f.introducedBy) : f.name;
  const file = vscode.workspace.asRelativePath(r.file);
  const tags = [
    f.direct ? '<span class="tag">direct</span>' : `<span class="tag" title="${esc(describeOrigin(f))}">via ${esc(root)}</span>`,
    f.dev ? '<span class="tag">dev only</span>' : '',
    prio.exploited ? `<span class="tag kevTag" title="At least one advisory is in CISA's Known Exploited Vulnerabilities catalog">🔥 exploited in the wild</span>` : '',
    !prio.exploited && prio.epss !== undefined && prio.epss >= EPSS_LIKELY ? `<span class="tag hotTag" title="EPSS: chance of exploitation in the next 30 days">likely exploited · EPSS ${pct(prio.epss)}</span>` : '',
    f.suspicious && !malicious ? `<span class="tag warnTag">⚠ suspicious · risk ${f.riskScore}</span>` : '',
    `<span class="tag proj">${esc(p.name)}</span>`,
    multiFile ? `<span class="tag file">${esc(file)}</span>` : '',
  ].join('');
  const shown = f.vulns.slice(0, 5);
  const rest = f.vulns.slice(5);
  const vulns = f.vulns.length
    ? `<ul class="adv">${shown.map(advisory).join('')}</ul>${rest.length ? `<details class="more"><summary>${plural(rest.length, 'more advisory', 'more advisories')}</summary><ul class="adv">${rest.map(advisory).join('')}</ul></details>` : ''}`
    : '';
  const sigs = f.signals.filter((s) => s.code !== 'known-malicious');
  const signals = sigs.length
    ? `<details class="more"${f.suspicious && !f.vulns.length ? ' open' : ''}><summary>Supply-chain signals (${sigs.length})</summary><ul class="sig">${sigs
        .map((s) => `<li><b>${esc(s.code)}</b> <span class="dim">+${s.score}</span> ${esc(s.message)}</li>`)
        .join('')}</ul></details>`
    : '';
  const chain = !f.direct && f.via.length > 1 ? `<div class="dim small chain">Path: ${esc([...f.via, f.key].join(' › '))}</div>` : '';
  const todo = todoText(f);
  const search = [f.name, f.version, p.name, file, root, ...f.vulns.flatMap((v) => [v.id, ...v.aliases, v.summary])].join(' ').toLowerCase();
  return `<article class="card ${level}" id="card-${it.ref}" data-ref="${it.ref}" data-proj="${p.id}" data-level="${level}" data-prio="${prio.priority}" data-fix="${prio.fix}"
 data-score="${prio.score}" data-cvss="${prio.cvss ?? -1}" data-n="${f.vulns.length}" data-name="${esc(f.name.toLowerCase())}" data-direct="${f.direct ? 1 : 0}" data-dev="${f.dev ? 1 : 0}"
 data-root="${esc(root)}" data-kev="${prio.exploited ? 1 : 0}" data-epss="${prio.epss ?? -1}" data-q="${esc(search)}">
  <div class="head">
    <span class="prio ${prio.priority}" title="${esc(PRIORITY_HINT[prio.priority])}">${PRIORITY_LABEL[prio.priority]}</span>
    <span class="name">${esc(f.name)}</span><span class="ver">${esc(f.version)}</span>${tags}
    <span class="grow"></span>
    <button class="ghost tiny" data-act="open" title="Open the line in ${esc(vscode.workspace.asRelativePath(r.manifestFile ?? r.file))}">Open in file</button>
  </div>
  <div class="todo ${todo.cls}">→ ${esc(todo.text)}</div>
  <div class="why">Why this priority: ${esc(prio.reasons.join(' · '))}</div>
  <div class="details">${vulns}${signals}${chain}</div>
</article>`;
}

function projectHeader(p: Project, s: ProjectStats): string {
  return `<span class="gtitle">${esc(p.name)}</span><span class="eco">${esc(ECOSYSTEM_LABEL[p.ecosystem])}</span><span class="chips">${chips(s)}</span>`;
}

function projectIntro(p: Project, s: ProjectStats): string {
  const files = p.results.map((r) => `${esc(vscode.workspace.asRelativePath(r.file))} <span class="dim">(${r.packageCount} pkgs)</span>`).join(' · ');
  const notes = p.results.filter((r) => r.error || r.warnings.length);
  return `<div class="files dim small">Scanned: ${files} · ${plural(s.affected, 'affected package')}</div>${
    notes.length
      ? `<div class="notes"><b>Notes</b><ul>${notes
          .map((r) => `<li>${r.error ? '<span class="pill critical">ERROR</span> ' : ''}<b>${esc(vscode.workspace.asRelativePath(r.file))}</b>: ${esc([r.error, ...r.warnings].filter(Boolean).join(' · '))}</li>`)
          .join('')}</ul></div>`
      : ''
  }`;
}

function render(results: FileResult[], lastScan: Date | undefined, csp: string): string {
  const nonce = randomBytes(16).toString('base64');
  const projects = groupProjects(results, workspaceRoots());
  const total = statsOf(results);

  refs = [];
  const items: Item[] = [];
  for (const p of projects)
    for (const r of p.results)
      for (const f of r.findings) {
        const ref = refs.push({ result: r, finding: f }) - 1;
        items.push({ ref, f, r, p, level: levelOf(f), prio: priorityOf(f) });
      }
  items.sort((a, b) => b.prio.score - a.prio.score || a.f.name.localeCompare(b.f.name));

  const levelCount = (l: Level) => items.filter((i) => i.level === l).length;
  const prioCount = (p: string) => items.filter((i) => i.prio.priority === p).length;

  const tiles = LEVELS.map((l) => {
    const n = levelCount(l);
    return `<button class="stat ${l}${n ? '' : ' zero'}" data-level-toggle="${l}" aria-pressed="false" ${n ? '' : 'disabled'} title="${n ? `Show only ${LEVEL_LABEL[l].toLowerCase()} packages` : ''}"><b>${n}</b><span>${LEVEL_LABEL[l]}</span></button>`;
  }).join('');

  const start = items.slice(0, 3);
  const startHere =
    items.length > 1
      ? `<div class="start"><div class="start-title">Start here</div><ol>${start
          .map(
            (i) =>
              `<li><span class="prio ${i.prio.priority}">${PRIORITY_LABEL[i.prio.priority]}</span> <a href="#card-${i.ref}"><b>${esc(i.f.name)}</b> ${esc(i.f.version)}</a>${projects.length > 1 ? ` <span class="dim">in ${esc(i.p.name)}</span>` : ''}<div class="dim small">${esc(todoText(i.f).text)}</div></li>`,
          )
          .join('')}</ol></div>`
      : '';

  const overview =
    projects.length > 1
      ? `<h2>Projects</h2><table class="overview"><thead><tr><th>Project</th><th>Type</th><th class="num">Packages</th><th>Issues</th></tr></thead><tbody>${projects
          .map((p) => {
            const s = statsOf(p.results);
            return `<tr><td><a href="#${p.id}" data-proj-link="${p.id}">${esc(p.name)}</a></td><td class="dim">${esc(ECOSYSTEM_LABEL[p.ecosystem])}</td><td class="num">${s.packages}</td><td>${chips(s)}</td></tr>`;
          })
          .join('')}</tbody></table>`
      : '';

  // Project templates drive the "group by project" view; the sections below are the same grouping for the first paint.
  const templates = projects
    .map((p) => {
      const s = statsOf(p.results);
      return `<template class="proj-tpl" data-id="${p.id}" data-total="${p.results.reduce((n, r) => n + r.findings.length, 0)}"><div class="h">${projectHeader(p, s)}</div><div class="i">${projectIntro(p, s)}</div></template>`;
    })
    .join('');
  const initial = projects
    .map((p) => {
      const s = statsOf(p.results);
      const mine = items.filter((i) => i.p === p);
      return `<section class="group" id="${p.id}"><details open><summary class="ghead">${projectHeader(p, s)}</summary><div class="gintro">${projectIntro(p, s)}</div><div class="gbody">${
        mine.length ? mine.map((i) => findingCard(i, p.results.length > 1)).join('') : '<p class="clean">✓ No known vulnerabilities or suspicious packages.</p>'
      }</div></details></section>`;
    })
    .join('');

  const labels = {
    prio: Object.fromEntries(PRIORITY_ORDER.map((p) => [p, { label: PRIORITY_LABEL[p], hint: PRIORITY_HINT[p] }])),
    fix: Object.fromEntries(FIX_ORDER.map((f) => [f, FIX_LABEL[f]])),
    level: LEVEL_LABEL,
    epssLikely: EPSS_LIKELY,
  };

  const toolbar = items.length
    ? `<div class="toolbar" role="toolbar" aria-label="Sort and filter">
  <div class="row">
    <input id="q" type="search" placeholder="Search packages, CVEs, projects…  ( / )" aria-label="Search">
    <label class="sel">Group by <select id="group">
      ${projects.length > 1 ? '<option value="project">Project</option>' : ''}
      <option value="priority">Priority</option>
      <option value="fix">Fix type</option>
      <option value="root">Dependency to update</option>
      <option value="severity">Severity</option>
      <option value="none">No grouping</option>
    </select></label>
    <label class="sel"><span id="sortLabel">Sort by</span> <select id="sort">
      <option value="priority">Priority (recommended)</option>
      <option value="exploit">Exploit activity (KEV, EPSS)</option>
      <option value="effort">Easiest fix first</option>
      <option value="cvss">CVSS score</option>
      <option value="severity">Severity</option>
      <option value="count">Most advisories</option>
      <option value="name">Name</option>
    </select></label>
  </div>
  <div class="row">
    <span class="lbl">Priority</span>
    ${PRIORITY_ORDER.map((p) => `<button class="toggle prio-t ${p}" data-prio-toggle="${p}" aria-pressed="false" title="${esc(PRIORITY_HINT[p])}" ${prioCount(p) ? '' : 'disabled'}>${PRIORITY_LABEL[p]} <span class="n">${prioCount(p)}</span></button>`).join('')}
    <span class="sep"></span>
    ${(() => {
      const n = items.filter((i) => i.prio.exploited || (i.prio.epss ?? 0) >= EPSS_LIKELY).length;
      const title = n
        ? `Exploited in the wild (CISA KEV) or EPSS ≥ ${pct(EPSS_LIKELY)}`
        : items.some((i) => i.f.vulns.some((v) => v.epss || v.kev))
          ? 'None of the advisories found is exploited in the wild or likely to be'
          : 'No exploit data in these results. Scan again, and check that depSentinel.exploitData.enabled is on';
      return `<label class="chk${n ? '' : ' off'}" title="${esc(title)}"><input type="checkbox" id="exploit" ${n ? '' : 'disabled'}> 🔥 Exploited or likely <span class="n">${n}</span></label>`;
    })()}
    <label class="chk"><input type="checkbox" id="fixable"> Has a fix</label>
    <label class="chk"><input type="checkbox" id="direct"> Direct only</label>
    <label class="chk"><input type="checkbox" id="hideDev"> Hide dev-only</label>
    <label class="chk"><input type="checkbox" id="compact"> Compact</label>
    <span class="grow"></span>
    <span id="shown" class="dim small"></span>
    <button class="ghost tiny" data-act="reset" id="reset" hidden>Reset filters</button>
  </div>
</div>`
    : '';

  const json = (v: unknown) => JSON.stringify(v).replace(/</g, '\\u003c');

  return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${csp} 'unsafe-inline'; script-src 'nonce-${nonce}';">
<style>
:root{--crit:#d32f2f;--high:#e8590c;--med:#c79100;--low:#3b7ddd;--mal:#8e24aa;--ok:#2e7d32;--border:var(--vscode-panel-border,#8884);--soft:color-mix(in srgb,var(--vscode-foreground) 5%,transparent);--radius:8px}
*{box-sizing:border-box}
body{font-family:var(--vscode-font-family);font-size:var(--vscode-font-size);color:var(--vscode-foreground);background:var(--vscode-editor-background);padding:0 28px 28px;max-width:1180px;margin:0 auto;line-height:1.45}
h1{font-size:20px;margin:22px 0 2px;display:flex;align-items:center;gap:10px}h2{font-size:14px;margin:26px 0 8px;text-transform:uppercase;letter-spacing:.06em;opacity:.75}
.dim{opacity:.7}.small{font-size:12px}.grow{flex:1}
a{color:var(--vscode-textLink-foreground);text-decoration:none}a:hover{text-decoration:underline}
button{font:inherit;color:inherit;cursor:pointer}button:disabled{cursor:default}
:focus-visible{outline:1px solid var(--vscode-focusBorder);outline-offset:1px}
.top{display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px}
.actions{display:flex;gap:6px}
.btn{background:var(--vscode-button-background);color:var(--vscode-button-foreground);border:0;border-radius:4px;padding:5px 12px}
.btn:hover{background:var(--vscode-button-hoverBackground)}
.btn.secondary{background:var(--vscode-button-secondaryBackground);color:var(--vscode-button-secondaryForeground)}
.btn.secondary:hover{background:var(--vscode-button-secondaryHoverBackground)}
.ghost{background:transparent;border:1px solid var(--border);border-radius:4px;padding:2px 8px}
.ghost:hover{background:var(--vscode-toolbar-hoverBackground,var(--soft))}
.tiny{font-size:11px;padding:1px 7px}
.banner{display:flex;gap:12px;align-items:flex-start;border-radius:var(--radius);padding:12px 16px;margin:16px 0;border:1px solid}
.bicon{flex:none;width:24px;height:24px;border-radius:50%;display:grid;place-items:center;font-weight:700;color:#fff}
.banner.bad{border-color:color-mix(in srgb,var(--crit) 45%,transparent);background:color-mix(in srgb,var(--crit) 10%,transparent)}.banner.bad .bicon{background:var(--crit)}
.banner.warn{border-color:color-mix(in srgb,var(--med) 45%,transparent);background:color-mix(in srgb,var(--med) 10%,transparent)}.banner.warn .bicon{background:var(--med)}
.banner.good{border-color:color-mix(in srgb,var(--ok) 45%,transparent);background:color-mix(in srgb,var(--ok) 10%,transparent)}.banner.good .bicon{background:var(--ok)}
.summary{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:14px;align-items:start}
@media (max-width:820px){.summary{grid-template-columns:1fr}}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.stat{text-align:left;background:var(--soft);border:1px solid var(--border);border-top:4px solid var(--border);border-radius:var(--radius);padding:8px 12px;transition:transform .08s,box-shadow .08s}
.stat:not(:disabled):hover{transform:translateY(-1px);box-shadow:0 2px 8px #0003}
.stat b{display:block;font-size:24px;line-height:1.15}.stat span{font-size:12px;opacity:.8}.stat.zero{opacity:.4}
.stat[aria-pressed=true]{outline:2px solid var(--vscode-focusBorder);outline-offset:-1px;background:color-mix(in srgb,var(--vscode-focusBorder) 12%,transparent)}
.stat.malicious{border-top-color:var(--mal)}.stat.critical{border-top-color:var(--crit)}.stat.high{border-top-color:var(--high)}
.stat.medium{border-top-color:var(--med)}.stat.low{border-top-color:var(--low)}.stat.suspicious{border-top-color:var(--med)}
.stats-note{grid-column:1/-1;font-size:11px;opacity:.6;margin-top:-2px}
.start{border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;background:var(--soft)}
.start-title{font-weight:700;margin-bottom:4px}.start ol{margin:0;padding-left:20px}.start li{margin:6px 0}
.chip{display:inline-block;font-size:11px;font-weight:600;padding:1px 8px;border-radius:10px;margin:1px 4px 1px 0;color:#fff;white-space:nowrap}
.pill{display:inline-block;flex:none;font-size:10.5px;font-weight:700;padding:0 6px;border-radius:3px;color:#fff;min-width:58px;text-align:center;line-height:18px}
.malicious.chip,.malicious.pill{background:var(--mal)}.critical.chip,.critical.pill{background:var(--crit)}.high.chip,.high.pill{background:var(--high)}
.medium.chip,.medium.pill,.unknown.pill{background:var(--med)}.low.chip,.low.pill{background:var(--low)}.suspicious.chip{background:var(--med)}.ok.chip{background:var(--ok)}
.prio{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:700;padding:1px 8px 1px 7px;border-radius:10px;border:1px solid;white-space:nowrap}
.prio::before{content:'';width:7px;height:7px;border-radius:50%;background:currentColor}
.prio.now{color:var(--crit);border-color:color-mix(in srgb,var(--crit) 55%,transparent);background:color-mix(in srgb,var(--crit) 12%,transparent)}
.prio.soon{color:var(--high);border-color:color-mix(in srgb,var(--high) 55%,transparent);background:color-mix(in srgb,var(--high) 12%,transparent)}
.prio.plan{color:var(--med);border-color:color-mix(in srgb,var(--med) 55%,transparent);background:color-mix(in srgb,var(--med) 12%,transparent)}
.prio.later{color:var(--low);border-color:color-mix(in srgb,var(--low) 55%,transparent);background:color-mix(in srgb,var(--low) 12%,transparent)}
table.overview{border-collapse:collapse;width:100%}
.overview th,.overview td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}.overview th{font-weight:600;opacity:.75;font-size:12px}.num{text-align:right!important}
.overview tbody tr:hover{background:var(--soft)}
.toolbar{position:sticky;top:0;z-index:5;background:var(--vscode-editor-background);border-bottom:1px solid var(--border);padding:10px 0 8px;margin:22px 0 6px;display:flex;flex-direction:column;gap:8px}
.toolbar .row{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}
#q{flex:1;min-width:220px;background:var(--vscode-input-background);color:var(--vscode-input-foreground);border:1px solid var(--vscode-input-border,var(--border));border-radius:4px;padding:5px 9px;font:inherit}
#q:focus{outline:1px solid var(--vscode-focusBorder);border-color:var(--vscode-focusBorder)}
.sel{font-size:12px;opacity:.9;display:flex;align-items:center;gap:6px}
select{background:var(--vscode-dropdown-background);color:var(--vscode-dropdown-foreground);border:1px solid var(--vscode-dropdown-border,var(--border));border-radius:4px;padding:4px 6px;font:inherit}
.lbl{font-size:12px;opacity:.75}
.toggle{font-size:12px;background:transparent;border:1px solid var(--border);border-radius:12px;padding:1px 10px}
.toggle .n{opacity:.7;margin-left:2px}.toggle:disabled{opacity:.4}
.toggle:not(:disabled):hover{background:var(--soft)}
.toggle[aria-pressed=true].now{background:var(--crit);border-color:var(--crit);color:#fff}.toggle[aria-pressed=true].soon{background:var(--high);border-color:var(--high);color:#fff}
.toggle[aria-pressed=true].plan{background:var(--med);border-color:var(--med);color:#fff}.toggle[aria-pressed=true].later{background:var(--low);border-color:var(--low);color:#fff}
.sep{width:1px;height:18px;background:var(--border)}
.chk{font-size:12px;display:flex;align-items:center;gap:4px;cursor:pointer;user-select:none}.chk .n{opacity:.7}.chk.off{opacity:.5;cursor:default}
.group{margin-top:14px}
summary.ghead{cursor:pointer;list-style:none;display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--soft)}
summary.ghead::-webkit-details-marker{display:none}
summary.ghead::before{content:'▸';opacity:.6;transition:transform .12s}details[open]>summary.ghead::before{transform:rotate(90deg)}
.gtitle{font-size:14px;font-weight:700}.eco,.ghint{opacity:.7;font-size:12px}.chips{margin-left:auto}.gcount{font-size:12px;opacity:.75;min-width:90px;text-align:right}
.files{margin:8px 2px 4px}.gintro:empty{display:none}
.card{border:1px solid var(--border);border-left:4px solid var(--low);border-radius:var(--radius);padding:10px 14px;margin:8px 0;transition:box-shadow .15s}
.card:hover{box-shadow:0 1px 6px #0002}
.card.malicious{border-left-color:var(--mal);background:color-mix(in srgb,var(--mal) 7%,transparent)}.card.critical{border-left-color:var(--crit)}
.card.high{border-left-color:var(--high)}.card.medium{border-left-color:var(--med)}.card.suspicious{border-left-color:var(--med);background:color-mix(in srgb,var(--med) 5%,transparent)}
.card.flash{animation:flash 1.4s ease-out}@keyframes flash{0%{box-shadow:0 0 0 3px var(--vscode-focusBorder)}100%{box-shadow:none}}
.head{display:flex;flex-wrap:wrap;align-items:center;gap:6px}.name{font-weight:700;font-size:14px}.ver{font-family:var(--vscode-editor-font-family);opacity:.8}
.tag{font-size:11px;padding:0 6px;border:1px solid var(--border);border-radius:3px;opacity:.85}.tag.warnTag{border-color:var(--med);color:var(--vscode-editorWarning-foreground);opacity:1}.tag.file{font-family:var(--vscode-editor-font-family)}
.tag.kevTag{border-color:var(--crit);background:var(--crit);color:#fff;font-weight:700;opacity:1}.tag.hotTag{border-color:var(--high);color:var(--high);font-weight:600;opacity:1}
.xb{flex:none;font-size:10.5px;font-weight:700;padding:0 6px;border-radius:3px;line-height:18px;white-space:nowrap;border:1px solid var(--border)}
.xb.kev{background:var(--crit);border-color:var(--crit);color:#fff}.xb.epss{font-weight:600;opacity:.8}.xb.epss.hot{border-color:var(--high);color:var(--high);opacity:1}
body.by-project .tag.proj{display:none}
.todo{margin:6px 0 2px;font-weight:600;color:var(--vscode-testing-iconPassed,var(--ok))}.todo.bad{color:var(--vscode-errorForeground)}.todo.warn{color:var(--vscode-editorWarning-foreground)}
.why{font-size:11.5px;opacity:.65;margin-bottom:4px}
body.compact .details,body.compact .why{display:none}body.compact .card{padding:7px 12px;margin:5px 0}
ul.adv{list-style:none;margin:6px 0 2px;padding:0}ul.adv li{display:flex;align-items:flex-start;gap:8px;padding:3px 4px;border-radius:4px}
ul.adv li:hover{background:var(--soft)}.advtext{flex:1}.sum{opacity:.9}
.ign{visibility:hidden}ul.adv li:hover .ign,.ign:focus-visible{visibility:visible}
.fixed{font-size:11px;color:var(--vscode-testing-iconPassed,var(--ok));white-space:nowrap}.nofix{font-size:11px;opacity:.6;white-space:nowrap}
details.more summary{cursor:pointer;font-size:12px;opacity:.8;margin-top:4px}
ul.sig{margin:4px 0 0 18px;padding:0;font-size:12px}.chain{margin-top:4px}
.clean{color:var(--vscode-testing-iconPassed,var(--ok));margin:8px 4px}
.empty{text-align:center;padding:30px;border:1px dashed var(--border);border-radius:var(--radius);margin-top:14px}
.notes{font-size:12px;margin:8px 2px}
footer{margin-top:32px;font-size:12px;opacity:.75;border-top:1px solid var(--border);padding-top:10px;display:grid;gap:6px}
footer .legend{display:flex;flex-wrap:wrap;gap:6px 16px;align-items:center}
</style></head><body>
<div class="top">
  <div class="grow">
    <h1>🛡 Dependency Security Report</h1>
    <div class="dim">Last scan: ${lastScan ? esc(lastScan.toLocaleString()) : 'never'} · ${plural(projects.length, 'project')} · ${total.packages} packages checked, including sub-dependencies</div>
  </div>
  <div class="actions"><button class="btn" data-act="scan">Scan again</button><button class="btn secondary" data-act="export">Export…</button></div>
</div>
${results.length ? verdict(total, projects.length, items.filter((i) => i.prio.exploited).length) : '<div class="banner warn"><span class="bicon">i</span><div>No scan results yet. Run <b>DepSentinel: Scan Dependencies Now</b>.</div></div>'}
${
  items.length
    ? `<div class="summary"><div class="stats">${tiles}<div class="stats-note">Affected packages by their worst problem. Click a tile to filter.</div></div>${startHere}</div>`
    : ''
}
${overview}
${toolbar}
<div id="groups">${initial}</div>
<div id="empty" class="empty" hidden>No packages match these filters. <button class="ghost tiny" data-act="reset">Reset filters</button></div>
${templates}
<footer>
<div class="legend"><b>Priority</b>${PRIORITY_ORDER.map((p) => `<span><span class="prio ${p}">${PRIORITY_LABEL[p]}</span> ${esc(PRIORITY_HINT[p])}</span>`).join('')}</div>
<div>Within a priority, higher CVSS scores, easy same-major upgrades and direct dependencies come first. <b>Malicious</b>: a known attack, remove now. <b>Suspicious</b>: shows signs of a supply-chain attack, review it.</div>
<div><b>🔥 Exploited</b>: listed in CISA's Known Exploited Vulnerabilities catalog; attackers are using it now, so it is fixed first. <b>EPSS</b>: estimated chance of exploitation in the next 30 days (FIRST.org); ${pct(EPSS_LIKELY)} or more raises the priority one step.</div>
<div>Sources: CISA KEV, FIRST EPSS, OSV.dev (CVE, GHSA, PYSEC, GO, RUSTSEC, OpenSSF Malicious Packages), deps.dev, npm registry.</div>
</footer>
<script type="application/json" id="labels">${json(labels)}</script>
<script nonce="${nonce}">${SCRIPT}</script>
</body></html>`;
}

/** Client-side sorting, grouping and filtering. Plain DOM; every string it inserts comes from the extension-escaped page. */
const SCRIPT = String.raw`(function () {
  const vscode = acquireVsCodeApi();
  const $ = (s) => document.querySelector(s);
  const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
  const L = JSON.parse($('#labels').textContent);
  const LEVELS = ['malicious', 'critical', 'high', 'suspicious', 'medium', 'low'];
  const PRIOS = ['now', 'soon', 'plan', 'later'];
  const FIXES = ['remove', 'quick', 'major', 'nofix', 'review'];
  const groupsEl = $('#groups');
  const tpls = $$('template.proj-tpl');
  const items = $$('.card').map((el) => {
    const d = el.dataset;
    return { el, ref: +d.ref, proj: d.proj, level: d.level, prio: d.prio, fix: d.fix, score: +d.score, cvss: +d.cvss, n: +d.n, name: d.name, root: d.root, direct: d.direct === '1', dev: d.dev === '1', kev: d.kev === '1', epss: +d.epss, q: d.q };
  });
  if (!items.length) { wireButtons(); return; }

  const groupSel = $('#group'), sortSel = $('#sort'), q = $('#q');
  const defaults = { group: groupSel.options[0].value, sort: 'priority', q: '', levels: [], prios: [], exploit: false, fixable: false, direct: false, hideDev: false, compact: false };
  const saved = vscode.getState() || {};
  const state = Object.assign({}, defaults, saved);
  if (!$$('option', groupSel).some((o) => o.value === state.group)) state.group = defaults.group;
  if (!$$('option', sortSel).some((o) => o.value === state.sort)) state.sort = defaults.sort;
  state.levels = (state.levels || []).filter((l) => LEVELS.includes(l));
  state.prios = (state.prios || []).filter((p) => PRIOS.includes(p));

  const filtering = () => !!(state.q || state.levels.length || state.prios.length || state.exploit || state.fixable || state.direct || state.hideDev);
  const matches = (it) =>
    (!state.levels.length || state.levels.includes(it.level)) &&
    (!state.prios.length || state.prios.includes(it.prio)) &&
    (!state.exploit || it.kev || it.epss >= L.epssLikely) &&
    (!state.fixable || it.fix === 'quick' || it.fix === 'major') &&
    (!state.direct || it.direct) &&
    (!state.hideDev || !it.dev) &&
    (!state.q || it.q.includes(state.q.toLowerCase()));

  const byScore = (a, b) => b.score - a.score || a.name.localeCompare(b.name);
  const SORTS = {
    priority: byScore,
    exploit: (a, b) => Number(b.kev) - Number(a.kev) || b.epss - a.epss || byScore(a, b),
    effort: (a, b) => FIXES.indexOf(a.fix) - FIXES.indexOf(b.fix) || byScore(a, b),
    cvss: (a, b) => b.cvss - a.cvss || byScore(a, b),
    severity: (a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level) || b.cvss - a.cvss || byScore(a, b),
    count: (a, b) => b.n - a.n || byScore(a, b),
    name: (a, b) => a.name.localeCompare(b.name) || byScore(a, b),
  };

  function el(tag, cls, html) { const e = document.createElement(tag); if (cls) e.className = cls; if (html !== undefined) e.innerHTML = html; return e; }
  function txt(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function levelChips(list) {
    return LEVELS.map((l) => { const n = list.filter((i) => i.level === l).length; return n ? '<span class="chip ' + l + '">' + n + ' ' + l + '</span>' : ''; }).join('');
  }
  const count = (shown, all) => (shown === all ? all + (all === 1 ? ' package' : ' packages') : shown + ' of ' + all + ' shown');

  function groupsFor(list) {
    const mk = (key, head, intro, members, all) => ({ key, head, intro: intro || '', members, all });
    const g = state.group;
    if (g === 'project') {
      return tpls.map((t) => {
        const id = t.dataset.id;
        const mine = list.filter((i) => i.proj === id);
        const all = items.filter((i) => i.proj === id).length;
        return mk(id, t.content.querySelector('.h').innerHTML, t.content.querySelector('.i').innerHTML, mine, all);
      }).filter((x) => x.members.length || (!filtering() && x.all === 0));
    }
    if (g === 'priority') return PRIOS.map((p) => mk('p-' + p, '<span class="prio ' + p + '">' + L.prio[p].label + '</span><span class="ghint">' + txt(L.prio[p].hint) + '</span>', '', list.filter((i) => i.prio === p), items.filter((i) => i.prio === p).length));
    if (g === 'severity') return LEVELS.map((l) => mk('s-' + l, '<span class="pill ' + l + '">' + L.level[l].toUpperCase() + '</span>', '', list.filter((i) => i.level === l), items.filter((i) => i.level === l).length));
    if (g === 'fix') return FIXES.map((f) => mk('f-' + f, '<span class="gtitle">' + txt(L.fix[f]) + '</span>', '', list.filter((i) => i.fix === f), items.filter((i) => i.fix === f).length));
    if (g === 'root') {
      const multi = tpls.length > 1;
      const names = Object.fromEntries(tpls.map((t) => [t.dataset.id, t.content.querySelector('.gtitle').textContent]));
      const keys = [];
      const map = new Map();
      for (const i of list) { const k = i.proj + '|' + i.root; if (!map.has(k)) { map.set(k, []); keys.push(k); } map.get(k).push(i); }
      return keys
        .map((k) => {
          const mine = map.get(k);
          const [proj, root] = [mine[0].proj, mine[0].root];
          const all = items.filter((i) => i.proj === proj && i.root === root).length;
          const head = '<span class="gtitle">' + txt(root) + '</span>' + (multi ? '<span class="eco">' + txt(names[proj]) + '</span>' : '') +
            '<span class="ghint">' + (all === 1 && mine[0].direct ? 'direct dependency' : 'brings in ' + all + ' affected package' + (all === 1 ? '' : 's')) + '</span>';
          return mk('r-' + k, head, '', mine, all);
        })
        .sort((a, b) => Math.max.apply(null, b.members.map((i) => i.score)) - Math.max.apply(null, a.members.map((i) => i.score)));
    }
    return [mk('all', '', '', list, items.length)];
  }

  function apply() {
    vscode.setState(state);
    document.body.classList.toggle('by-project', state.group === 'project');
    document.body.classList.toggle('compact', state.compact);
    $('#sortLabel').textContent = state.group === 'none' ? 'Sort by' : 'Sort each group by';
    const shown = items.filter(matches).sort(SORTS[state.sort]);
    const frag = document.createDocumentFragment();
    for (const g of groupsFor(shown).filter((x) => x.members.length || state.group === 'project')) {
      const body = el('div', 'gbody');
      if (g.members.length) g.members.forEach((i) => body.appendChild(i.el));
      else body.appendChild(el('p', 'clean', '✓ No known vulnerabilities or suspicious packages.'));
      if (g.key === 'all') { frag.appendChild(body); continue; }
      const sec = el('section', 'group');
      sec.id = state.group === 'project' ? g.key : 'g-' + g.key.replace(/[^\w-]/g, '_');
      const det = el('details');
      det.open = true;
      const sum = el('summary', 'ghead', g.head);
      if (!sum.querySelector('.chips')) sum.insertAdjacentHTML('beforeend', '<span class="chips">' + (state.group === 'severity' ? '' : levelChips(g.members)) + '</span>');
      if (g.all) sum.insertAdjacentHTML('beforeend', '<span class="gcount">' + count(g.members.length, g.all) + '</span>');
      det.appendChild(sum);
      if (g.intro) det.appendChild(el('div', 'gintro', g.intro));
      det.appendChild(body);
      sec.appendChild(det);
      frag.appendChild(sec);
    }
    groupsEl.replaceChildren(frag);
    $('#empty').hidden = shown.length > 0;
    $('#shown').textContent = filtering() ? count(shown.length, items.length) : items.length + ' affected packages';
    $('#reset').hidden = !filtering();
    $$('[data-level-toggle]').forEach((b) => b.setAttribute('aria-pressed', String(state.levels.includes(b.dataset.levelToggle))));
    $$('[data-prio-toggle]').forEach((b) => b.setAttribute('aria-pressed', String(state.prios.includes(b.dataset.prioToggle))));
  }

  function sync() {
    groupSel.value = state.group; sortSel.value = state.sort; q.value = state.q;
    ['exploit', 'fixable', 'direct', 'hideDev', 'compact'].forEach((k) => ($('#' + k).checked = !!state[k]));
  }
  function reset() { Object.assign(state, { q: '', levels: [], prios: [], exploit: false, fixable: false, direct: false, hideDev: false }); sync(); apply(); }
  const toggle = (arr, v) => (arr.includes(v) ? arr.filter((x) => x !== v) : arr.concat(v));

  groupSel.addEventListener('change', () => { state.group = groupSel.value; apply(); });
  sortSel.addEventListener('change', () => { state.sort = sortSel.value; apply(); });
  let t;
  q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { state.q = q.value.trim(); apply(); }, 120); });
  ['exploit', 'fixable', 'direct', 'hideDev', 'compact'].forEach((k) => $('#' + k).addEventListener('change', (e) => { state[k] = e.target.checked; apply(); }));
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== q) { e.preventDefault(); q.focus(); }
    else if (e.key === 'Escape' && document.activeElement === q) { q.value = ''; state.q = ''; apply(); }
  });

  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-level-toggle],[data-prio-toggle],[data-act=reset]');
    if (b) {
      if (b.dataset.levelToggle) state.levels = toggle(state.levels, b.dataset.levelToggle);
      else if (b.dataset.prioToggle) state.prios = toggle(state.prios, b.dataset.prioToggle);
      else return reset();
      return apply();
    }
    const a = e.target.closest('a[href^="#"]');
    if (!a) return;
    e.preventDefault();
    const id = a.getAttribute('href').slice(1);
    if (a.dataset.projLink && state.group !== 'project') { state.group = 'project'; sync(); apply(); }
    let target = document.getElementById(id);
    if (id.startsWith('card-') && !groupsEl.contains(document.getElementById(id))) { reset(); target = document.getElementById(id); }
    if (!target) return;
    const det = target.closest('details'); if (det) det.open = true;
    target.scrollIntoView({ behavior: 'smooth', block: id.startsWith('card-') ? 'center' : 'start' });
    if (target.classList.contains('card')) { target.classList.remove('flash'); void target.offsetWidth; target.classList.add('flash'); }
  });

  wireButtons();
  sync();
  apply();

  function wireButtons() {
    document.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-act]');
      if (!b) return;
      const card = b.closest('.card');
      const ref = card ? +card.dataset.ref : undefined;
      if (b.dataset.act === 'open') vscode.postMessage({ type: 'open', ref });
      else if (b.dataset.act === 'ignore') vscode.postMessage({ type: 'ignore', ref, id: b.dataset.id });
      else if (b.dataset.act === 'scan') vscode.postMessage({ type: 'scan' });
      else if (b.dataset.act === 'export') vscode.postMessage({ type: 'export' });
    });
  }
})();`;
