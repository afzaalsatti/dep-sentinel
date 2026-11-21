import * as path from 'path';
import * as vscode from 'vscode';
import { computeVersionEdit } from './core/bump';
import { planMavenPin, planNpmOverride } from './core/overrides';
import type { Ecosystem } from './core/types';
import type { DiagnosticsManager } from './diagnostics';

export const QUICKFIX_SELECTOR: vscode.DocumentSelector = [
  { scheme: 'file', pattern: '**/package.json' },
  { scheme: 'file', pattern: '**/pom.xml' },
  { scheme: 'file', pattern: '**/requirements*.txt' },
  { scheme: 'file', pattern: '**/*.gradle' },
  { scheme: 'file', pattern: '**/*.gradle.kts' },
  { scheme: 'file', pattern: '**/go.mod' },
];

/** Command that refreshes a lockfile after its manifest was edited. Only runs when the user clicks it. */
/**
 * Lockfile-only refresh commands. They rewrite the lockfile without downloading into node_modules and,
 * crucially, without running any package's install scripts – so accepting the offer can never execute
 * code from the project or from the (possibly malicious) dependency being replaced.
 * Yarn has no portable equivalent across v1/Berry, so the user is only told what to run.
 */
const LOCK_REFRESH: Record<string, string> = {
  'package-lock.json': 'npm install --package-lock-only --ignore-scripts',
  'npm-shrinkwrap.json': 'npm install --package-lock-only --ignore-scripts',
  'pnpm-lock.yaml': 'pnpm install --lockfile-only --ignore-scripts',
};

export class UpgradeQuickFixProvider implements vscode.CodeActionProvider {
  static readonly kinds = [vscode.CodeActionKind.QuickFix];

  constructor(private readonly diagnostics: DiagnosticsManager) {}

  provideCodeActions(doc: vscode.TextDocument, range: vscode.Range, context: vscode.CodeActionContext): vscode.CodeAction[] {
    const ours = context.diagnostics.filter((d) => d.source === 'DepSentinel');
    if (!ours.length) return [];
    const actions: vscode.CodeAction[] = [];
    const text = doc.getText();

    const counted = (k: number, n: number) => (k === n ? `fixes ${n} advisor${n > 1 ? 'ies' : 'y'}` : `fixes ${k} of ${n}`);
    for (const fix of this.diagnostics.fixesAt(doc.uri.fsPath, range.start.line, range.end.line)) {
      const finish = (action: vscode.CodeAction) => {
        action.diagnostics = ours.filter((d) => d.range.start.line === fix.line && d.message.includes(`${fix.name}@${fix.version}`));
        action.command = { command: 'depSentinel.afterUpgrade', title: 'After upgrade', arguments: [fix.ecosystem, doc.uri.fsPath, fix.scannedFile] };
        actions.push(action);
      };
      if (fix.kind === 'upgrade') {
        // Same-major upgrade first (preferred), then the "fixes everything" major upgrade, clearly labelled.
        const options: { target: string; label: string; preferred: boolean }[] = [];
        if (fix.safeTarget) options.push({ target: fix.safeTarget, label: `Upgrade ${fix.name} to ${fix.safeTarget} (${counted(fix.safeCount, fix.advisoryCount)})`, preferred: true });
        if (fix.target !== fix.safeTarget) options.push({ target: fix.target, label: `Upgrade ${fix.name} to ${fix.target} ⚠ major version (${counted(fix.advisoryCount, fix.advisoryCount)})`, preferred: false });
        for (const o of options) {
          const edit = computeVersionEdit(text, doc.uri.fsPath, fix.name, fix.line, o.target);
          if (!edit) continue;
          const action = new vscode.CodeAction(o.label, vscode.CodeActionKind.QuickFix);
          action.edit = new vscode.WorkspaceEdit();
          action.edit.replace(doc.uri, new vscode.Range(edit.line, edit.start, edit.line, edit.end), edit.newText);
          action.isPreferred = o.preferred;
          finish(action);
        }
      } else if (fix.safeTarget) {
        const isPom = path.basename(doc.uri.fsPath) === 'pom.xml';
        const plan = isPom ? planMavenPin(text, fix.name, fix.safeTarget) : planNpmOverride(text, fix.scannedFile, fix.name, fix.version, fix.safeTarget);
        if (!plan) continue;
        const how = isPom ? 'dependencyManagement' : path.basename(fix.scannedFile) === 'yarn.lock' ? 'resolutions, all copies' : 'overrides';
        const action = new vscode.CodeAction(`Force transitive ${fix.name} ${fix.version} → ${fix.safeTarget} via ${how} (${counted(fix.safeCount, fix.advisoryCount)})`, vscode.CodeActionKind.QuickFix);
        action.edit = new vscode.WorkspaceEdit();
        for (const e of plan.edits) action.edit.replace(doc.uri, new vscode.Range(doc.positionAt(e.offset), doc.positionAt(e.offset + e.length)), e.content);
        finish(action);
      }
    }

    const seen = new Set<string>();
    for (const d of ours) {
      const id = typeof d.code === 'object' ? String(d.code.value) : undefined;
      if (!id || seen.has(id)) continue;
      seen.add(id);
      const open = new vscode.CodeAction(`Open advisory ${id}`, vscode.CodeActionKind.QuickFix);
      open.command = { command: 'depSentinel.openAdvisory', title: 'Open', arguments: [id, typeof d.code === 'object' ? d.code.target.toString() : undefined] };
      actions.push(open);
      const ignore = new vscode.CodeAction(`Ignore ${id} in this workspace`, vscode.CodeActionKind.QuickFix);
      ignore.command = { command: 'depSentinel.ignoreAdvisory', title: 'Ignore', arguments: [id] };
      actions.push(ignore);
    }
    return actions;
  }
}

/** Shown after an upgrade quick fix: remind the user that the lockfile (the scanned file) is now stale. */
export async function afterUpgrade(_ecosystem: Ecosystem, manifest: string, scannedFile: string) {
  if (path.resolve(manifest) === path.resolve(scannedFile)) return; // the manifest itself is scanned – the file watcher re-scans it
  const lockName = path.basename(scannedFile);
  const cmd = LOCK_REFRESH[lockName];
  // Never offer to run anything in a workspace the user hasn't trusted.
  if (!cmd || !vscode.workspace.isTrusted) {
    vscode.window.showInformationMessage(`Updated ${path.basename(manifest)}. Regenerate ${lockName} so DepSentinel sees the new version.`);
    return;
  }
  const pick = await vscode.window.showInformationMessage(
    `Updated ${path.basename(manifest)}. ${lockName} still pins the old version – run "${cmd}" to refresh it.`,
    `Run ${cmd}`,
  );
  if (pick) {
    const term = vscode.window.createTerminal({ name: 'DepSentinel', cwd: path.dirname(scannedFile) });
    term.show();
    term.sendText(cmd);
  }
}
