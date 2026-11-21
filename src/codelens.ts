import * as vscode from 'vscode';
import { cfg } from './config';
import { findingSeverity } from './core/exporters';
import { SEVERITY_RANK, type PackageFinding, type Severity } from './core/types';
import type { DiagnosticsManager, LineSummary } from './diagnostics';

const worst = (list: PackageFinding[]): Severity =>
  list.map(findingSeverity).reduce<Severity>((m, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[m] ? s : m), 'low');

/** Short title for the lens above an affected dependency line. Exported for tests. */
export function lensTitle(s: LineSummary): string {
  const parts: string[] = [];
  const d = s.direct;
  if (d?.vulns.some((v) => v.isMalicious)) return '$(bug) MALICIOUS package – remove it';
  if (d) {
    if (d.vulns.length) {
      const sev = findingSeverity(d);
      parts.push(`$(shield) ${d.vulns.length} vulnerabilit${d.vulns.length > 1 ? 'ies' : 'y'} (${sev})`);
      const target = d.safeFixVersion ?? d.fixVersion;
      if (target) parts.push(`fix → ${target}${!d.safeFixVersion ? ' (major)' : ''}`);
    }
    if (d.suspicious) parts.push('$(warning) suspicious');
  }
  if (s.transitive.length) {
    const mal = s.transitive.filter((t) => t.vulns.some((v) => v.isMalicious)).length;
    if (mal) parts.push(`$(bug) ${mal} malicious sub-dependenc${mal > 1 ? 'ies' : 'y'}`);
    const rest = s.transitive.length - mal;
    if (rest) parts.push(`${d ? '+' : '$(type-hierarchy)'} ${rest} vulnerable sub-dependenc${rest > 1 ? 'ies' : 'y'} (worst: ${worst(s.transitive.filter((t) => !t.vulns.some((v) => v.isMalicious)))})`);
  }
  return parts.join(' · ');
}

export class FindingsCodeLensProvider implements vscode.CodeLensProvider {
  private emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.emitter.event;

  constructor(private readonly diagnostics: DiagnosticsManager) {
    diagnostics.onDidChange(() => this.emitter.fire());
  }

  refresh() {
    this.emitter.fire();
  }

  provideCodeLenses(doc: vscode.TextDocument): vscode.CodeLens[] {
    if (!cfg().get('codeLens', true)) return [];
    return this.diagnostics
      .linesIn(doc.uri.fsPath)
      .filter((s) => s.line < doc.lineCount)
      .map((s) => {
        const title = lensTitle(s);
        return title
          ? new vscode.CodeLens(doc.lineAt(s.line).range, { title, tooltip: 'DepSentinel – click for fixes and details', command: 'depSentinel.lineActions', arguments: [doc.uri, s.line] })
          : undefined;
      })
      .filter((l): l is vscode.CodeLens => !!l);
  }
}
