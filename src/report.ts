import * as vscode from 'vscode';
import { describeFix, describeOrigin } from './diagnostics';
import type { FileResult } from './core/types';

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

let panel: vscode.WebviewPanel | undefined;

export function showReport(results: FileResult[], lastScan: Date | undefined) {
  if (!panel) {
    panel = vscode.window.createWebviewPanel('depSentinel.report', 'DepSentinel Report', vscode.ViewColumn.Active, { enableScripts: false, enableCommandUris: false });
    panel.onDidDispose(() => (panel = undefined));
  }
  panel.webview.html = render(results, lastScan, panel.webview.cspSource);
  panel.reveal();
}

export function refreshReport(results: FileResult[], lastScan: Date | undefined) {
  if (panel) panel.webview.html = render(results, lastScan, panel.webview.cspSource);
}

function render(results: FileResult[], lastScan: Date | undefined, csp: string): string {
  const findings = results.flatMap((r) => r.findings.map((f) => ({ r, f })));
  const vulnCount = (sev: string) => findings.reduce((n, { f }) => n + f.vulns.filter((v) => v.severity === sev).length, 0);
  const suspicious = findings.filter(({ f }) => f.suspicious).length;
  const malicious = findings.filter(({ f }) => f.vulns.some((v) => v.isMalicious)).length;
  const packages = results.reduce((n, r) => n + r.packageCount, 0);

  const rows = findings
    .map(({ r, f }) => {
      const vulns = f.vulns
        .map(
          (v) =>
            `<div class="v"><span class="sev ${v.isMalicious ? 'critical' : v.severity}">${v.isMalicious ? 'MALICIOUS' : esc(v.severity.toUpperCase())}${v.cvssScore !== undefined ? ` ${v.cvssScore}` : ''}</span> <a href="${esc(v.url)}">${esc(v.aliases.find((a) => a.startsWith('CVE-')) ?? v.id)}</a> ${esc(v.summary)}${
              v.fixedVersions.length ? ` <span class="fix">fix: ${esc(v.fixedVersions.slice(0, 3).join(', '))}</span>` : ' <span class="nofix">no fix</span>'
            }</div>`,
        )
        .join('');
      const signals = f.signals.length
        ? `<ul class="sig">${f.signals.map((s) => `<li><b>${esc(s.code)}</b> (+${s.score}) ${esc(s.message)}</li>`).join('')}</ul>`
        : '';
      return `<tr class="${f.suspicious ? 'sus' : ''}">
        <td><b>${esc(f.name)}</b>@${esc(f.version)}${f.suspicious ? '<div class="badge">⚠ SUSPICIOUS · score ' + f.riskScore + '</div>' : ''}</td>
        <td>${esc(describeOrigin(f))}${f.dev ? ' <i>(dev)</i>' : ''}</td>
        <td>${esc(vscode.workspace.asRelativePath(r.file))}</td>
        <td>${f.vulns.length && !f.vulns.some((v) => v.isMalicious) ? `<div class="rec">${esc(describeFix(f).trim())}</div>` : ''}${vulns}${signals}</td></tr>`;
    })
    .join('');

  const errors = results.filter((r) => r.error || r.warnings.length);
  return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${csp} 'unsafe-inline';">
<style>
body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);padding:16px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0 20px}
.card{border:1px solid var(--vscode-panel-border);border-radius:6px;padding:10px 16px;min-width:110px}
.card b{display:block;font-size:22px}
table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid var(--vscode-panel-border);padding:8px;vertical-align:top;text-align:left}
tr.sus{background:color-mix(in srgb, var(--vscode-editorWarning-foreground) 10%, transparent)}
.sev{font-weight:600;padding:1px 6px;border-radius:3px;font-size:11px;color:#fff}
.critical{background:#b00020}.high{background:#d9480f}.medium{background:#b08800}.low{background:#3b7ddd}.unknown{background:#666}
.rec{font-weight:600;margin-bottom:4px;color:var(--vscode-testing-iconPassed)}
.v{margin:2px 0}.fix{color:var(--vscode-testing-iconPassed)}.nofix{opacity:.7}
.badge{color:var(--vscode-editorWarning-foreground);font-weight:600;margin-top:4px}
.sig{margin:4px 0 0 16px;padding:0;font-size:12px;opacity:.9}
a{color:var(--vscode-textLink-foreground)}
</style></head><body>
<h2>DepSentinel – Dependency Security Report</h2>
<div>Last scan: ${lastScan ? esc(lastScan.toLocaleString()) : 'never'} · ${results.length} manifest(s) · ${packages} packages (incl. transitive)</div>
<div class="cards">
<div class="card"><b>${vulnCount('critical')}</b>Critical</div>
<div class="card"><b>${vulnCount('high')}</b>High</div>
<div class="card"><b>${vulnCount('medium') + vulnCount('unknown')}</b>Medium</div>
<div class="card"><b>${vulnCount('low')}</b>Low</div>
<div class="card"><b>${suspicious}</b>Suspicious</div>
<div class="card"><b>${malicious}</b>Malicious</div>
</div>
${findings.length ? `<table><tr><th>Package</th><th>Origin</th><th>File</th><th>Issues</th></tr>${rows}</table>` : '<p>✅ No known vulnerabilities or suspicious packages found.</p>'}
${errors.length ? `<h3>Notes</h3><ul>${errors.map((r) => `<li><b>${esc(vscode.workspace.asRelativePath(r.file))}</b>: ${esc([r.error, ...r.warnings].filter(Boolean).join(' · '))}</li>`).join('')}</ul>` : ''}
<p style="opacity:.7;font-size:12px">Sources: OSV.dev (CVE, GHSA, PYSEC, GO, RUSTSEC, OpenSSF Malicious Packages), deps.dev, npm registry.</p>
</body></html>`;
}
