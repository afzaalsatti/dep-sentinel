import { promises as fs } from 'fs';
import * as vscode from 'vscode';
import { locatePackage } from './core/locate';
import { describeFixText } from './core/versions';
import type { Ecosystem, FileResult, PackageFinding, Severity } from './core/types';

export function nameOfKey(key: string): string {
  const at = key.lastIndexOf('@');
  return at > 0 ? key.slice(0, at) : key;
}

function toDiagSeverity(s: Severity): vscode.DiagnosticSeverity {
  switch (s) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
    case 'unknown':
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

export function describeOrigin(f: PackageFinding): string {
  if (f.direct) return 'direct dependency';
  if (f.via.length) return `transitive via ${f.via.map(nameOfKey).join(' › ')}`;
  return 'transitive dependency';
}

export function describeFix(f: PackageFinding): string {
  const text = describeFixText(f);
  return text ? ` ${text}` : '';
}

type TextCache = Map<string, Promise<string | undefined>>;

function readText(file: string, cache?: TextCache): Promise<string | undefined> {
  let p = cache?.get(file);
  if (!p) {
    p = fs.readFile(file, 'utf8').catch(() => undefined);
    cache?.set(file, p);
  }
  return p;
}

/** File where diagnostics for a finding are shown, and the line. */
export async function findingLocation(result: FileResult, f: PackageFinding, cache?: TextCache): Promise<{ file: string; line: number }> {
  const file = result.manifestFile ?? result.file;
  const text = await readText(file, cache);
  const lookupName = f.direct ? f.name : f.introducedBy ? nameOfKey(f.introducedBy) : f.name;
  let line = text ? locatePackage(text, file, lookupName, f.version) : undefined;
  if (line === undefined && file !== result.file) {
    const lockText = await readText(result.file, cache);
    const l = lockText ? locatePackage(lockText, result.file, f.name, f.version) : undefined;
    if (l !== undefined) return { file: result.file, line: l };
  }
  if (line === undefined && text && !f.direct) line = locatePackage(text, file, f.name, f.version);
  return { file, line: line ?? 0 };
}

/** Data the quick-fix provider needs to offer an upgrade. */
export interface FixInfo {
  /** `upgrade` edits the declared version of a direct dep; `override` forces a transitive dep (npm overrides / Maven dependencyManagement). */
  kind: 'upgrade' | 'override';
  file: string;
  line: number;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** Version fixing every fixable advisory (may be a new major). */
  target: string;
  advisoryCount: number;
  /** Best version on the current major line, and how many advisories it fixes. */
  safeTarget?: string;
  safeCount: number;
  scannedFile: string;
}

/** Per-line summary used by CodeLens. */
export interface LineSummary {
  file: string;
  line: number;
  /** The declared dependency on this line (if it is itself affected). */
  direct?: PackageFinding;
  /** Vulnerable / suspicious packages pulled in through this line's dependency. */
  transitive: PackageFinding[];
}

export class DiagnosticsManager implements vscode.Disposable {
  private collection = vscode.languages.createDiagnosticCollection('depSentinel');
  private byFile = new Map<string, Map<string, vscode.Diagnostic[]>>();
  private fixes = new Map<string, FixInfo[]>(); // scanned file -> fixes
  private lines = new Map<string, LineSummary[]>(); // scanned file -> line summaries
  private changed = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changed.event;

  async update(result: FileResult) {
    const cache: TextCache = new Map();
    const perFile = new Map<string, vscode.Diagnostic[]>();
    const fixes: FixInfo[] = [];
    const summaries = new Map<string, LineSummary>();
    for (const f of result.findings) {
      const { file, line } = await findingLocation(result, f, cache);
      const sk = `${file}|${line}`;
      const summary = summaries.get(sk) ?? { file, line, transitive: [] };
      if (f.direct) summary.direct = f;
      else summary.transitive.push(f);
      summaries.set(sk, summary);
      const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
      const list = perFile.get(file) ?? [];
      const origin = describeOrigin(f);
      const fixText = describeFix(f);
      for (const v of f.vulns.slice(0, 5)) {
        const cve = v.aliases.find((a) => a.startsWith('CVE-'));
        const d = new vscode.Diagnostic(
          range,
          `${v.isMalicious ? '☠ MALICIOUS PACKAGE ' : ''}${f.name}@${f.version} (${origin}${f.dev ? ', dev' : ''}): [${v.severity.toUpperCase()}${v.cvssScore !== undefined ? ` ${v.cvssScore}` : ''}] ${v.summary}${cve && cve !== v.id ? ` (${cve})` : ''}.${fixText}`,
          v.isMalicious ? vscode.DiagnosticSeverity.Error : toDiagSeverity(v.severity),
        );
        d.source = 'DepSentinel';
        d.code = { value: v.id, target: vscode.Uri.parse(v.url) };
        list.push(d);
      }
      if (f.vulns.length > 5) {
        const d = new vscode.Diagnostic(range, `${f.name}@${f.version}: ${f.vulns.length - 5} more advisories – see the DepSentinel view.${fixText}`, vscode.DiagnosticSeverity.Information);
        d.source = 'DepSentinel';
        list.push(d);
      }
      const notable = f.signals.filter((s) => s.score >= 3 || f.suspicious);
      if (notable.length && !f.vulns.some((v) => v.isMalicious)) {
        const d = new vscode.Diagnostic(
          range,
          `${f.suspicious ? '⚠ SUSPICIOUS' : 'Supply-chain risk'}: ${f.name}@${f.version} (${origin}, risk score ${f.riskScore}) – ${notable.map((s) => s.message).join(' | ')}`,
          f.suspicious ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information,
        );
        d.source = 'DepSentinel';
        d.code = 'supply-chain';
        list.push(d);
      }
      perFile.set(file, list);
      if (f.fixVersion && !f.vulns.some((v) => v.isMalicious)) {
        const base = {
          file,
          line,
          ecosystem: f.ecosystem,
          name: f.name,
          version: f.version,
          target: f.fixVersion,
          advisoryCount: f.vulns.length - (f.unfixed?.length ?? 0),
          safeTarget: f.safeFixVersion,
          safeCount: f.safeFixCount ?? 0,
          scannedFile: result.file,
        };
        if (f.direct) fixes.push({ kind: 'upgrade', ...base });
        // Forcing a transitive dependency onto a new major would likely break its parent – only offer same-major.
        else if (f.safeFixVersion && /(^|[\\/])(package\.json|pom\.xml)$/.test(file)) fixes.push({ kind: 'override', ...base });
      }
    }
    this.byFile.set(result.file, perFile);
    this.fixes.set(result.file, fixes);
    this.lines.set(result.file, [...summaries.values()]);
    this.render();
  }

  /** Line summaries for a document (CodeLens). */
  linesIn(file: string): LineSummary[] {
    const target = vscode.Uri.file(file).toString();
    return [...this.lines.values()].flat().filter((s) => vscode.Uri.file(s.file).toString() === target);
  }

  /** Upgrade fixes declared on the given lines of a file. */
  fixesAt(file: string, startLine: number, endLine: number): FixInfo[] {
    const norm = (p: string) => vscode.Uri.file(p).toString();
    const target = norm(file);
    return [...this.fixes.values()].flat().filter((x) => norm(x.file) === target && x.line >= startLine && x.line <= endLine);
  }

  remove(scannedFile: string) {
    this.byFile.delete(scannedFile);
    this.fixes.delete(scannedFile);
    this.lines.delete(scannedFile);
    this.render();
  }

  clear() {
    this.byFile.clear();
    this.fixes.clear();
    this.lines.clear();
    this.collection.clear();
    this.changed.fire();
  }

  private render() {
    const merged = new Map<string, vscode.Diagnostic[]>();
    for (const perFile of this.byFile.values()) {
      for (const [f, diags] of perFile) merged.set(f, [...(merged.get(f) ?? []), ...diags]);
    }
    this.collection.clear();
    for (const [f, diags] of merged) this.collection.set(vscode.Uri.file(f), diags);
    this.changed.fire();
  }

  dispose() {
    this.collection.dispose();
    this.changed.dispose();
  }
}
