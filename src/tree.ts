import * as path from 'path';
import * as vscode from 'vscode';
import { describeFix, describeOrigin } from './diagnostics';
import type { FileResult, PackageFinding, Severity, SupplyChainSignal, Vulnerability } from './core/types';

export type SummaryState = 'ok' | 'issues' | 'scanning' | 'error' | 'idle' | 'paused' | 'empty';

export type Node =
  | { kind: 'summary'; label: string; detail: string; state: SummaryState }
  | { kind: 'file'; result: FileResult }
  | { kind: 'pkg'; result: FileResult; finding: PackageFinding }
  | { kind: 'vuln'; finding: PackageFinding; vuln: Vulnerability }
  | { kind: 'signal'; finding: PackageFinding; signal: SupplyChainSignal }
  | { kind: 'warnings'; result: FileResult }
  | { kind: 'text'; text: string; icon?: string };

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

  set(results: FileResult[], summary: Extract<Node, { kind: 'summary' }>) {
    this.results = results;
    this.summary = summary;
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
      return [...(this.summary ? [this.summary] : []), ...extra, ...files.map((result): Node => ({ kind: 'file', result }))];
    }
    switch (node.kind) {
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
        item.description = `${v.severity.toUpperCase()}${v.cvssScore !== undefined ? ` ${v.cvssScore}` : ''} · ${v.summary}`;
        item.iconPath = v.isMalicious ? new vscode.ThemeIcon('bug', new vscode.ThemeColor('errorForeground')) : sevIcon(v.severity);
        item.contextValue = 'vuln';
        const md = new vscode.MarkdownString(
          `**${v.id}** ${v.aliases.length ? `(${v.aliases.join(', ')})` : ''}\n\n**Severity:** ${v.severity}${v.cvssScore !== undefined ? ` (CVSS ${v.cvssScore})` : ''}\n\n${v.summary}\n\n**Fixed in:** ${v.fixedVersions.join(', ') || 'no fix yet'}\n\n[Open advisory](${v.url})`,
        );
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
        item.tooltip = node.text;
        if (node.icon) item.iconPath = new vscode.ThemeIcon(node.icon);
        return item;
      }
    }
  }
}

function pkgTooltip(f: PackageFinding): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.appendMarkdown(`**${f.name}@${f.version}** — ${describeOrigin(f)}${f.dev ? ' (dev)' : ''}\n\n`);
  if (f.vulns.length) md.appendMarkdown(f.vulns.map((v) => `- **${v.severity.toUpperCase()}** ${v.id}: ${v.summary}`).join('\n') + '\n\n');
  if (f.vulns.length) md.appendMarkdown(`**Fix:**${describeFix(f)}\n\n`);
  if (f.signals.length) md.appendMarkdown(`**Supply-chain risk score:** ${f.riskScore}${f.suspicious ? ' — **SUSPICIOUS**' : ''}\n\n` + f.signals.map((s) => `- ${s.message}`).join('\n'));
  return md;
}

export function relativeName(file: string) {
  return vscode.workspace.asRelativePath(file) || path.basename(file);
}
