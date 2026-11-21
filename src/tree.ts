import * as path from 'path';
import { pct } from './core/exploit';
import * as vscode from 'vscode';
import { describeFix, describeOrigin } from './diagnostics';
import { safeExternalUrl } from './core/http';
import { ECOSYSTEM_LABEL, groupProjects, Project, statsOf } from './core/projects';
import type { FileResult, PackageFinding, Severity, SupplyChainSignal, Vulnerability } from './core/types';

export type SummaryState = 'ok' | 'issues' | 'scanning' | 'error' | 'idle' | 'paused' | 'empty';

export type Node =
  | { kind: 'summary'; label: string; detail: string; state: SummaryState }
  | { kind: 'project'; project: Project }
  | { kind: 'file'; result: FileResult }
  | { kind: 'pkg'; result: FileResult; finding: PackageFinding }
  | { kind: 'vuln'; finding: PackageFinding; vuln: Vulnerability }
  | { kind: 'signal'; finding: PackageFinding; signal: SupplyChainSignal }
  | { kind: 'warnings'; result: FileResult }
  | { kind: 'text'; text: string; icon?: string; tooltip?: string; command?: vscode.Command };

const sevIcon = (s: Severity, suspicious = false) => {
  if (s === 'critical') return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
  if (s === 'high') return new vscode.ThemeIcon('error', new vscode.ThemeColor('list.errorForeground'));
  if (suspicious || s === 'medium' || s === 'unknown') return new vscode.ThemeIcon('warning', new vscode.ThemeColor('list.warningForeground'));
  return new vscode.ThemeIcon('info');
};

export type FindingFilter = 'all' | 'severe' | 'supplyChain' | 'direct' | 'production';

export const FILTERS: { id: FindingFilter; label: string; detail: string }[] = [
  { id: 'all', label: 'All findings', detail: 'Show everything' },
  { id: 'severe', label: 'Critical & high only', detail: 'Critical/high vulnerabilities, suspicious and malicious packages' },
  { id: 'supplyChain', label: 'Supply-chain risks only', detail: 'Malicious, suspicious and risk-flagged packages' },
  { id: 'direct', label: 'Direct dependencies only', detail: 'Packages you declare yourself' },
  { id: 'production', label: 'Hide dev dependencies', detail: 'Only what ships to production' },
];

export function matchesFilter(f: PackageFinding, filter: FindingFilter): boolean {
  switch (filter) {
    case 'severe':
      return f.suspicious || f.vulns.some((v) => v.isMalicious || v.severity === 'critical' || v.severity === 'high');
    case 'supplyChain':
      return f.suspicious || f.vulns.some((v) => v.isMalicious) || f.signals.some((s) => s.score >= 3);
    case 'direct':
      return f.direct;
    case 'production':
      return !f.dev;
    default:
      return true;
  }
}

export class FindingsTree implements vscode.TreeDataProvider<Node> {
  private emitter = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  private results: FileResult[] = [];
  private summary: Extract<Node, { kind: 'summary' }> | undefined;
  filter: FindingFilter = 'all';

  setFilter(filter: FindingFilter) {
    this.filter = filter;
    this.emitter.fire(undefined);
  }

  private visible(r: FileResult): PackageFinding[] {
    return r.findings.filter((f) => matchesFilter(f, this.filter));
  }

  private notes: Node[] = [];

  set(results: FileResult[], summary: Extract<Node, { kind: 'summary' }>, notes: Node[] = []) {
    this.results = results;
    this.summary = summary;
    this.notes = notes;
    this.emitter.fire(undefined);
  }

  setSummary(summary: Extract<Node, { kind: 'summary' }>) {
    this.summary = summary;
    this.emitter.fire(undefined);
  }

  getChildren(node?: Node): Node[] {
    if (!node) {
      const files = this.results
        .filter((r) => this.visible(r).length || r.error || (this.filter === 'all' && r.warnings.length))
        .sort((a, b) => this.visible(b).length - this.visible(a).length);
      if (!this.summary && files.length === 0) return [];
      const extra: Node[] = [];
      if (this.summary && this.summary.state !== 'scanning' && this.results.length && !files.length) {
        extra.push(
          this.filter === 'all'
            ? { kind: 'text', text: `All ${this.results.length} manifest(s) are clean – no known vulnerabilities or suspicious packages`, icon: 'pass' }
            : { kind: 'text', text: 'Nothing matches the current filter', icon: 'filter' },
        );
      }
      const head = [...(this.summary ? [this.summary] : []), ...this.notes, ...extra];
      const roots = (vscode.workspace.workspaceFolders ?? []).map((f) => ({ name: f.name, path: f.uri.fsPath }));
      const projects = groupProjects(this.results, roots);
      if (projects.length > 1) {
        const shown = new Set(files);
        return [...head, ...projects.filter((p) => p.results.some((r) => shown.has(r))).map((project): Node => ({ kind: 'project', project }))];
      }
      return [...head, ...files.map((result): Node => ({ kind: 'file', result }))];
    }
    switch (node.kind) {
      case 'project': {
        const rs = node.project.results;
        if (rs.length === 1) return this.getChildren({ kind: 'file', result: rs[0] });
        return rs
          .filter((r) => this.filter === 'all' || this.visible(r).length || r.error)
          .map((result): Node => ({ kind: 'file', result }));
      }
      case 'file': {
        const out: Node[] = this.visible(node.result).map((finding) => ({ kind: 'pkg', result: node.result, finding }));
        if (node.result.error) out.unshift({ kind: 'text', text: `Error: ${node.result.error}`, icon: 'error' });
        if (node.result.warnings.length) out.push({ kind: 'warnings', result: node.result });
        if (!node.result.findings.length && !node.result.error) out.unshift({ kind: 'text', text: 'No vulnerabilities or suspicious packages', icon: 'pass' });
        return out;
      }
      case 'pkg':
        return [
          ...node.finding.vulns.map((vuln): Node => ({ kind: 'vuln', finding: node.finding, vuln })),
          ...node.finding.signals.map((signal): Node => ({ kind: 'signal', finding: node.finding, signal })),
          ...(node.finding.via.length ? [{ kind: 'text', text: `Path: ${[...node.finding.via, node.finding.key].join(' › ')}`, icon: 'type-hierarchy' } as Node] : []),
        ];
      case 'warnings':
        return node.result.warnings.map((text): Node => ({ kind: 'text', text, icon: 'info' }));
      default:
        return [];
    }
  }

  getTreeItem(node: Node): vscode.TreeItem {
    const None = vscode.TreeItemCollapsibleState.None;
    switch (node.kind) {
      case 'summary': {
        const item = new vscode.TreeItem(node.label, None);
        item.description = node.detail;
        item.iconPath = new vscode.ThemeIcon(
          node.state === 'scanning' ? 'sync~spin' : node.state === 'ok' ? 'pass' : node.state === 'error' ? 'error' : node.state === 'paused' ? 'debug-pause' : 'shield',
        );
        item.tooltip = 'Click to open the full report';
        item.command = { command: 'depSentinel.showReport', title: 'Show report' };
        return item;
      }
      case 'project': {
        const p = node.project;
        const shown = p.results.flatMap((r) => this.visible(r));
        const s = statsOf(p.results);
        const item = new vscode.TreeItem(p.name, shown.length ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed);
        const vulns = shown.reduce((n, f) => n + f.vulns.length, 0);
        const sus = shown.filter((f) => f.suspicious).length;
        const files = p.results.length === 1 ? path.basename(p.results[0].file) : `${p.results.length} files`;
        item.description = `${p.ecosystem} · ${files} · ${s.packages} pkgs · ${vulns ? `${vulns} vulns` : 'clean'}${sus ? ` · ${sus} suspicious` : ''}`;
        const worst = s.malicious || s.critical ? 'critical' : s.high ? 'high' : s.suspicious || s.medium ? 'medium' : s.low ? 'low' : undefined;
        item.iconPath = p.results.some((r) => r.error)
          ? new vscode.ThemeIcon('error')
          : worst
            ? new vscode.ThemeIcon('project', new vscode.ThemeColor(worst === 'critical' ? 'errorForeground' : worst === 'high' ? 'list.errorForeground' : worst === 'medium' ? 'list.warningForeground' : 'foreground'))
            : new vscode.ThemeIcon('project', new vscode.ThemeColor('testing.iconPassed'));
        item.tooltip = [p.name, ECOSYSTEM_LABEL[p.ecosystem], ...p.results.map((r) => vscode.workspace.asRelativePath(r.file))].join('\n');
        item.contextValue = 'project';
        return item;
      }
      case 'file': {
        const r = node.result;
        const rel = vscode.workspace.asRelativePath(r.file);
        const shown = this.visible(r);
        const item = new vscode.TreeItem(rel, shown.length ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed);
        const vulns = shown.reduce((n, f) => n + f.vulns.length, 0);
        const sus = shown.filter((f) => f.suspicious).length;
        item.description = `${r.ecosystem} · ${r.packageCount} pkgs · ${vulns} vulns${sus ? ` · ${sus} suspicious` : ''}`;
        item.iconPath = r.error ? new vscode.ThemeIcon('error') : vscode.ThemeIcon.File;
        item.resourceUri = vscode.Uri.file(r.file);
        item.tooltip = r.file;
        item.contextValue = 'file';
        return item;
      }
      case 'pkg': {
        const f = node.finding;
        const item = new vscode.TreeItem(`${f.name}@${f.version}`, vscode.TreeItemCollapsibleState.Collapsed);
        const parts = [f.direct ? 'direct' : f.introducedBy ? `via ${f.introducedBy}` : 'transitive'];
        if (f.dev) parts.push('dev');
        if (f.vulns.length) parts.push(`${f.vulns.length} vuln${f.vulns.length > 1 ? 's' : ''}`);
        if (f.fixVersion && !f.vulns.some((v) => v.isMalicious)) {
          if (!f.safeFixVersion) parts.push(`fix → ${f.fixVersion} (major)`);
          else parts.push(`fix → ${f.safeFixVersion}${f.safeFixVersion !== f.fixVersion ? ` · all: ${f.fixVersion}` : ''}`);
        }
        if (f.suspicious) parts.push('⚠ SUSPICIOUS');
        if (f.vulns.some((v) => v.kev)) parts.unshift('🔥 exploited');
        item.description = parts.join(' · ');
        item.iconPath = sevIcon(f.maxSeverity, f.suspicious);
        item.contextValue = f.suspicious ? 'pkg-suspicious' : 'pkg';
        item.tooltip = pkgTooltip(f);
        item.command = { command: 'depSentinel.revealInFile', title: 'Reveal', arguments: [node] };
        return item;
      }
      case 'vuln': {
        const v = node.vuln;
        const item = new vscode.TreeItem(v.aliases.find((a) => a.startsWith('CVE-')) ?? v.id, None);
        item.description = `${v.kev ? '🔥 EXPLOITED · ' : ''}${v.severity.toUpperCase()}${v.cvssScore !== undefined ? ` ${v.cvssScore}` : ''}${v.epss ? ` · EPSS ${pct(v.epss.score)}` : ''} · ${v.summary}`;
        item.iconPath = v.isMalicious ? new vscode.ThemeIcon('bug', new vscode.ThemeColor('errorForeground')) : sevIcon(v.severity);
        item.contextValue = 'vuln';
        // Advisory data is untrusted network content: escape it, and only link vetted http(s) URLs.
        const md = new vscode.MarkdownString();
        md.appendMarkdown('**').appendText(v.id).appendMarkdown('** ');
        if (v.aliases.length) md.appendText(`(${v.aliases.join(', ')})`);
        md.appendMarkdown(`\n\n**Severity:** ${v.severity}${v.cvssScore !== undefined ? ` (CVSS ${v.cvssScore})` : ''}\n\n`);
        if (v.kev) md.appendMarkdown(`**🔥 Exploited in the wild:** listed in CISA KEV since ${v.kev.dateAdded}${v.kev.ransomware ? ', used in ransomware campaigns' : ''}.\n\n`);
        if (v.epss) md.appendMarkdown(`**Exploit likelihood (EPSS):** ${pct(v.epss.score)} in the next 30 days, higher than ${Math.floor(v.epss.percentile * 100)}% of CVEs.\n\n`);
        md.appendText(v.summary);
        md.appendMarkdown('\n\n**Fixed in:** ').appendText(v.fixedVersions.join(', ') || 'no fix yet');
        const url = safeExternalUrl(v.url);
        if (url) md.appendMarkdown(`\n\n[Open advisory](${url.replace(/\(/g, '%28').replace(/\)/g, '%29')})`);
        item.tooltip = md;
        item.command = { command: 'depSentinel.openAdvisory', title: 'Open advisory', arguments: [node] };
        return item;
      }
      case 'signal': {
        const s = node.signal;
        const item = new vscode.TreeItem(s.message, None);
        item.description = `${s.code} (+${s.score})`;
        item.iconPath = new vscode.ThemeIcon(s.score >= 4 ? 'shield' : 'circle-small', s.score >= 4 ? new vscode.ThemeColor('list.warningForeground') : undefined);
        item.tooltip = s.message;
        return item;
      }
      case 'warnings': {
        const item = new vscode.TreeItem(`Notes (${node.result.warnings.length})`, vscode.TreeItemCollapsibleState.Collapsed);
        item.iconPath = new vscode.ThemeIcon('info');
        return item;
      }
      case 'text': {
        const item = new vscode.TreeItem(node.text, None);
        item.tooltip = node.tooltip ?? node.text;
        if (node.icon) item.iconPath = new vscode.ThemeIcon(node.icon);
        if (node.command) item.command = node.command;
        return item;
      }
    }
  }
}

function pkgTooltip(f: PackageFinding): vscode.MarkdownString {
  // Package names, advisory summaries and signal messages may contain attacker-controlled text: always escape.
  const md = new vscode.MarkdownString();
  md.appendMarkdown('**').appendText(`${f.name}@${f.version}`).appendMarkdown('** — ').appendText(`${describeOrigin(f)}${f.dev ? ' (dev)' : ''}`);
  md.appendMarkdown('\n\n');
  for (const v of f.vulns) md.appendMarkdown(`- **${v.severity.toUpperCase()}** `).appendText(`${v.id}: ${v.summary}`).appendMarkdown('\n');
  if (f.vulns.length) md.appendMarkdown('\n**Fix:** ').appendText(describeFix(f).trim()).appendMarkdown('\n\n');
  if (f.signals.length) {
    md.appendMarkdown(`**Supply-chain risk score:** ${f.riskScore}${f.suspicious ? ' — **SUSPICIOUS**' : ''}\n\n`);
    for (const s of f.signals) md.appendMarkdown('- ').appendText(s.message).appendMarkdown('\n');
  }
  return md;
}

export function relativeName(file: string) {
  return vscode.workspace.asRelativePath(file) || path.basename(file);
}
