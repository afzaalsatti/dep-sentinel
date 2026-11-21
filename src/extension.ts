import * as path from 'path';
import * as vscode from 'vscode';
import { appendToSetting, cfg, configProblems, readCoreConfig, SECTION, suppressionSummary } from './config';
import { FileCache } from './core/cache';
import { Http } from './core/http';
import { discoverScanTargets, MANIFEST_GLOB } from './core/parsers';
import { ECOSYSTEM_LABEL, groupProjects, statsOf } from './core/projects';
import { issueIds, Scanner } from './core/scanner';
import type { CoreContext, FileResult, Logger } from './core/types';
import { DiagnosticsManager, findingLocation } from './diagnostics';
import { refreshReport, showReport, workspaceRoots } from './report';
import { FILTERS, FindingFilter, FindingsTree, Node, SummaryState } from './tree';
import { afterUpgrade, QUICKFIX_SELECTOR, UpgradeQuickFixProvider } from './quickfix';
import { FindingsCodeLensProvider } from './codelens';
import { toMarkdown, toSarif } from './core/exporters';
import { readTextFile } from './core/fsutil';
import { safeExternalUrl } from './core/http';

const MINUTE = 60_000;
const OFFLINE_RETRY_MS = 5 * MINUTE;

const STATE_RESULTS = 'depSentinel.results';
const STATE_KNOWN = 'depSentinel.knownIssues';
const STATE_LAST_SCAN = 'depSentinel.lastScan';
const STATE_FILTER = 'depSentinel.filter';
const STATE_PAUSED = 'depSentinel.paused';
const STATE_WELCOMED = 'depSentinel.welcomed';
const STATE_RESULTS_FORMAT = 'depSentinel.resultsFormat';
/** Bump when scan results gain data an update should show right away (2: CISA KEV / EPSS exploit data). */
const RESULTS_FORMAT = 2;
const WALKTHROUGH = 'depSentinel.gettingStarted';

export async function activate(context: vscode.ExtensionContext) {
  const controller = new Controller(context);
  await controller.init();
  context.subscriptions.push(controller);
  return controller.api;
}

export interface DepSentinelApi {
  getResults(): FileResult[];
  tree: FindingsTree;
  isScanning(): boolean;
  badge(): vscode.ViewBadge | undefined;
  isPaused(): boolean;
  statusText(): string;
  codeLens: FindingsCodeLensProvider;
}

export function deactivate() {}

/** "5 min ago" / "in 42 min" */
function relative(d: Date): string {
  const diff = d.getTime() - Date.now();
  const mins = Math.round(Math.abs(diff) / MINUTE);
  const text = mins < 1 ? 'less than a minute' : mins < 60 ? `${mins} min` : mins < 48 * 60 ? `${Math.round(mins / 60)} h` : `${Math.round(mins / 1440)} days`;
  return diff < 0 ? `${text} ago` : `in ${text}`;
}

class Controller implements vscode.Disposable {
  private readonly output = vscode.window.createOutputChannel('DepSentinel', { log: true });
  private readonly diagnostics = new DiagnosticsManager();
  private readonly tree = new FindingsTree();
  private readonly status = vscode.window.createStatusBarItem('depSentinel.status', vscode.StatusBarAlignment.Right, 100);
  private readonly cache: FileCache;
  private readonly http = new Http();
  private readonly disposables: vscode.Disposable[] = [];
  private results = new Map<string, FileResult>();
  /** Wall-clock time of the next scheduled scan. Checked by a ticker, so it survives sleep/hibernate. */
  private nextDue = Number.POSITIVE_INFINITY;
  private ticker: NodeJS.Timeout | undefined;
  private view: vscode.TreeView<Node> | undefined;
  private scanning = false;
  private pendingFull = false;
  private pendingFiles = new Set<string>();
  private changeTimer: NodeJS.Timeout | undefined;
  private cancelRequested = false;
  private lastScan: Date | undefined;
  private lastError: string | undefined;
  private paused = false;
  private progressPct = 0;
  private progressMsg = '';
  private lastProgressUi = 0;
  private noManifests = false;
  private readonly codeLens = new FindingsCodeLensProvider(this.diagnostics);

  constructor(private readonly context: vscode.ExtensionContext) {
    this.cache = new FileCache(path.join(context.globalStorageUri.fsPath, 'cache'));
  }

  readonly api: DepSentinelApi = {
    getResults: () => [...this.results.values()],
    tree: this.tree,
    isScanning: () => this.scanning,
    badge: () => this.view?.badge,
    isPaused: () => this.paused,
    statusText: () => this.status.text,
    codeLens: this.codeLens,
  };

  private get log(): Logger {
    return {
      info: (m) => this.output.info(m),
      warn: (m) => this.output.warn(m),
      error: (m) => this.output.error(m),
    };
  }

  async init() {
    await this.cache.load(['pom', 'osv-vuln', 'release-facts', 'npm-version-v2', 'npm-abbrev', 'versions', 'kev', 'epss']);

    this.view = vscode.window.createTreeView('depSentinel.findings', { treeDataProvider: this.tree, showCollapseAll: true });
    this.disposables.push(
      this.view,
      this.output,
      this.diagnostics,
      this.status,
      vscode.languages.registerCodeActionsProvider(QUICKFIX_SELECTOR, new UpgradeQuickFixProvider(this.diagnostics), {
        providedCodeActionKinds: UpgradeQuickFixProvider.kinds,
      }),
      vscode.languages.registerCodeLensProvider(QUICKFIX_SELECTOR, this.codeLens),
    );

    this.status.name = 'DepSentinel';
    this.status.command = 'depSentinel.menu';
    this.status.show();

    this.paused = this.context.workspaceState.get<boolean>(STATE_PAUSED, false);
    void vscode.commands.executeCommand('setContext', 'depSentinel.paused', this.paused);
    this.applyFilter(this.context.workspaceState.get<FindingFilter>(STATE_FILTER, 'all'));

    this.registerCommands();
    this.registerWatchers();
    this.warnConfigProblems();
    void this.welcomeOnce();

    // Restore last results so issues are visible immediately.
    const saved = this.context.workspaceState.get<FileResult[]>(STATE_RESULTS);
    const last = this.context.workspaceState.get<string>(STATE_LAST_SCAN);
    if (last) this.lastScan = new Date(last);
    if (saved) {
      for (const r of saved) this.results.set(r.file, r);
      await Promise.all(saved.map((r) => this.diagnostics.update(r)));
    }
    this.refreshUi();

    const intervalMs = this.intervalMs();
    // Results saved by an older version lack newer data (e.g. exploit activity): show them, but re-scan right away.
    const outdated = !!saved && this.context.workspaceState.get<number>(STATE_RESULTS_FORMAT, 1) < RESULTS_FORMAT;
    const due = outdated || !this.lastScan || Date.now() - this.lastScan.getTime() >= intervalMs;
    if (cfg().get('scanOnStartup', true) && due) {
      setTimeout(() => void this.scanAll('startup'), 3000);
    } else {
      this.schedule(this.lastScan ? Math.max(10_000, intervalMs - (Date.now() - this.lastScan.getTime())) : intervalMs);
    }
    // A wall-clock ticker instead of one long setTimeout: long timers drift or are lost when the machine sleeps.
    this.ticker = setInterval(() => {
      if (!this.paused && !this.scanning && Date.now() >= this.nextDue) void this.scanAll('scheduled');
    }, 30_000);
  }

  /** One-time hint after installation pointing at the walkthrough. */
  private async welcomeOnce() {
    if (this.context.globalState.get<boolean>(STATE_WELCOMED)) return;
    await this.context.globalState.update(STATE_WELCOMED, true);
    if (this.context.extensionMode === vscode.ExtensionMode.Test) return;
    const pick = await vscode.window.showInformationMessage(
      'DepSentinel is now watching your dependencies for known vulnerabilities and supply-chain attacks. Results appear in the shield view, the Problems panel and above each dependency.',
      'Get Started',
      'Show Findings',
    );
    if (pick === 'Get Started') void vscode.commands.executeCommand('depSentinel.gettingStarted');
    if (pick === 'Show Findings') void vscode.commands.executeCommand('depSentinel.findings.focus');
  }

  /** Make suppression visible: ignored advisories / trusted packages are listed, and flagged if they come from the repo itself. */
  private suppressionNotes(): Node[] {
    const s = suppressionSummary();
    if (!s.ignored.length && !s.trusted.length) return [];
    const parts = [s.ignored.length ? `${s.ignored.length} ignored advisor${s.ignored.length > 1 ? 'ies' : 'y'}` : '', s.trusted.length ? `${s.trusted.length} trusted package${s.trusted.length > 1 ? 's' : ''}` : '']
      .filter(Boolean)
      .join(', ');
    return [
      {
        kind: 'text',
        text: `Suppressed by settings: ${parts}${s.fromWorkspace ? ' (set by this workspace)' : ''}`,
        icon: s.fromWorkspace ? 'warning' : 'eye-closed',
        tooltip: [
          s.fromWorkspace ? '⚠ Some suppressions come from this repository\'s .vscode/settings.json – review them; a malicious repository could hide its own findings this way.' : '',
          s.ignored.length ? `Ignored advisories: ${s.ignored.join(', ')}` : '',
          s.trusted.length ? `Trusted packages: ${s.trusted.join(', ')}` : '',
          'Click to review in Settings.',
        ]
          .filter(Boolean)
          .join('\n'),
        command: { command: 'workbench.action.openSettings', title: 'Review', arguments: [`@ext:${this.context.extension.id} ignoredAdvisories trustedPackages`] },
      },
    ];
  }

  private warnConfigProblems() {
    for (const p of configProblems()) {
      this.log.warn(p);
      void vscode.window.showWarningMessage(`DepSentinel: ${p}`, 'Open Settings').then((pick) => pick && vscode.commands.executeCommand('depSentinel.openSettings'));
    }
  }

  private applyFilter(filter: FindingFilter) {
    this.tree.setFilter(filter);
    if (this.view) this.view.description = filter === 'all' ? undefined : `Filter: ${FILTERS.find((f) => f.id === filter)?.label}`;
    void vscode.commands.executeCommand('setContext', 'depSentinel.filtered', filter !== 'all');
  }

  private async setPaused(paused: boolean) {
    this.paused = paused;
    await this.context.workspaceState.update(STATE_PAUSED, paused);
    await vscode.commands.executeCommand('setContext', 'depSentinel.paused', paused);
    this.log.info(paused ? 'Monitoring paused' : 'Monitoring resumed');
    this.refreshUi();
    if (!paused && Date.now() >= this.nextDue) void this.scanAll('resumed');
  }

  /** Export the current results. `targetUri` skips the save dialog (automation/tests). */
  private async exportReport(format?: 'markdown' | 'sarif' | 'json', targetUri?: vscode.Uri) {
    if (!this.results.size) {
      vscode.window.showWarningMessage('DepSentinel: nothing to export yet – run a scan first.');
      return;
    }
    const choice =
      format ??
      (
        await vscode.window.showQuickPick(
          [
            { label: '$(markdown) Markdown', description: 'Share in a PR, ticket or chat', id: 'markdown' as const },
            { label: '$(json) SARIF 2.1.0', description: 'GitHub code scanning, Azure DevOps, other SAST tools', id: 'sarif' as const },
            { label: '$(file-code) JSON', description: 'Full raw results', id: 'json' as const },
          ],
          { title: 'Export DepSentinel report', placeHolder: 'Choose a format' },
        )
      )?.id;
    if (!choice) return;
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
    const ext = { markdown: 'md', sarif: 'sarif', json: 'json' }[choice];
    const target =
      targetUri ??
      (await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(path.join(root, `depsentinel-report.${ext}`)),
        filters: { [choice.toUpperCase()]: [ext] },
        title: 'Save DepSentinel report',
      }));
    if (!target) return;
    const results = [...this.results.values()];
    const content =
      choice === 'markdown' ? toMarkdown(results, root, this.lastScan) : JSON.stringify(choice === 'sarif' ? await toSarif(results, root) : results, null, 2);
    await vscode.workspace.fs.writeFile(target, Buffer.from(content, 'utf8'));
    if (targetUri) return;
    const open = await vscode.window.showInformationMessage(`Report saved to ${vscode.workspace.asRelativePath(target)}.`, 'Open');
    if (open) {
      if (choice === 'markdown') void vscode.commands.executeCommand('markdown.showPreview', target);
      else void vscode.window.showTextDocument(target);
    }
  }

  private async showMenu() {
    type Item = vscode.QuickPickItem & { run?: () => unknown };
    const sep = (label: string): Item => ({ label, kind: vscode.QuickPickItemKind.Separator });
    const items: Item[] = [
      ...(this.scanning ? [{ label: '$(debug-stop) Cancel scan', description: `${this.progressPct}% · ${this.progressMsg}`, run: () => (this.cancelRequested = true) }] : []),
      { label: '$(refresh) Scan now', description: this.lastScan ? `last scan ${relative(this.lastScan)}` : 'never scanned', run: () => this.scanAll('manual') },
      { label: '$(list-tree) Show findings', run: () => vscode.commands.executeCommand('depSentinel.findings.focus') },
      { label: '$(preview) Open report', run: () => vscode.commands.executeCommand('depSentinel.showReport') },
      { label: '$(export) Export report…', description: 'Markdown, SARIF or JSON', run: () => this.exportReport() },
      { label: '$(filter) Filter findings…', description: FILTERS.find((f) => f.id === this.tree.filter)?.label, run: () => vscode.commands.executeCommand('depSentinel.filter') },
      ...this.projectItems(sep),
      sep('Monitoring'),
      this.paused
        ? { label: '$(debug-start) Resume monitoring', description: 'hourly checks and on-change scans are paused', run: () => this.setPaused(false) }
        : { label: '$(debug-pause) Pause monitoring', description: `next check ${Number.isFinite(this.nextDue) ? relative(new Date(this.nextDue)) : 'soon'}`, run: () => this.setPaused(true) },
      { label: '$(gear) Settings', run: () => vscode.commands.executeCommand('depSentinel.openSettings') },
      { label: '$(trash) Clear cache', description: 'forget cached advisories and registry data', run: () => vscode.commands.executeCommand('depSentinel.clearCache') },
      sep('Help'),
      { label: '$(book) Getting started', run: () => vscode.commands.executeCommand('depSentinel.gettingStarted') },
      { label: '$(output) Show log', run: () => this.output.show() },
    ];
    const pick = await vscode.window.showQuickPick(items, { title: 'DepSentinel', placeHolder: 'What would you like to do?' });
    await pick?.run?.();
  }

  /** One menu row per project, so a mixed workspace (e.g. a Java API next to a React app) shows each one's status. */
  private projectItems(sep: (label: string) => vscode.QuickPickItem & { run?: () => unknown }): (vscode.QuickPickItem & { run?: () => unknown })[] {
    const projects = groupProjects([...this.results.values()], workspaceRoots());
    if (!projects.length) return [];
    return [
      sep(`Projects (${projects.length})`),
      ...projects.map((p) => {
        const s = statsOf(p.results);
        const issues = [
          s.malicious && `${s.malicious} malicious`,
          s.critical && `${s.critical} critical`,
          s.high && `${s.high} high`,
          s.suspicious && `${s.suspicious} suspicious`,
          s.medium + s.low && `${s.medium + s.low} medium/low`,
        ]
          .filter(Boolean)
          .join(', ');
        const icon = s.malicious || s.critical || s.high ? '$(error)' : s.affected ? '$(warning)' : '$(pass)';
        return {
          label: `${icon} ${p.name}`,
          description: `${ECOSYSTEM_LABEL[p.ecosystem]} · ${s.packages} pkgs`,
          detail: issues || 'no known issues',
          run: () => vscode.commands.executeCommand('depSentinel.showReport'),
        };
      }),
    ];
  }

  private intervalMs() {
    return Math.max(5, cfg().get('scanIntervalMinutes', 60)) * MINUTE;
  }

  private schedule(ms = this.intervalMs()) {
    this.nextDue = Date.now() + ms;
    this.log.info(`Next scheduled scan at ${new Date(this.nextDue).toLocaleTimeString()}`);
  }

  private registerCommands() {
    const reg = (id: string, fn: (...args: any[]) => unknown) => this.disposables.push(vscode.commands.registerCommand(id, fn));
    reg('depSentinel.scanNow', () => this.scanAll('manual'));
    reg('depSentinel.showReport', () => showReport([...this.results.values()], this.lastScan));
    reg('depSentinel.showLog', () => this.output.show());
    // Tree items pass a Node; quick fixes pass (advisoryId, url).
    reg('depSentinel.openAdvisory', (arg?: Node | string, url?: string) => {
      const raw = typeof arg === 'string' ? url ?? `https://osv.dev/vulnerability/${encodeURIComponent(arg)}` : arg?.kind === 'vuln' ? arg.vuln.url : undefined;
      // Advisory URLs come from the network: only ever open http(s) links (never command:, file:, vscode: …).
      const target = safeExternalUrl(raw);
      if (target) void vscode.env.openExternal(vscode.Uri.parse(target));
      else if (raw) this.log.warn(`Blocked opening non-web advisory link: ${raw}`);
    });
    reg('depSentinel.afterUpgrade', afterUpgrade);
    reg('depSentinel.revealInFile', async (node?: Node) => {
      if (node?.kind !== 'pkg') return;
      const loc = await findingLocation(node.result, node.finding);
      const doc = await vscode.workspace.openTextDocument(loc.file);
      const editor = await vscode.window.showTextDocument(doc, { preview: true });
      const range = doc.lineAt(Math.min(loc.line, doc.lineCount - 1)).range;
      editor.selection = new vscode.Selection(range.start, range.end);
      editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    });
    reg('depSentinel.ignoreAdvisory', async (arg?: Node | string) => {
      const id = typeof arg === 'string' ? arg : arg?.kind === 'vuln' ? arg.vuln.id : undefined;
      if (!id) return;
      const pick = await vscode.window.showWarningMessage(`Ignore ${id} in this workspace?`, { modal: true }, 'Ignore');
      if (pick === 'Ignore') await appendToSetting('ignoredAdvisories', id);
    });
    reg('depSentinel.trustPackage', async (node?: Node) => {
      if (node?.kind !== 'pkg') return;
      const id = `${node.finding.name}@${node.finding.version}`;
      const pick = await vscode.window.showWarningMessage(
        `Suppress supply-chain warnings for ${id}? Only do this after you have reviewed the package.`,
        { modal: true },
        'Trust this version',
      );
      if (pick) await appendToSetting('supplyChain.trustedPackages', id);
    });
    reg('depSentinel.clearCache', async () => {
      await this.cache.clear();
      vscode.window.showInformationMessage('DepSentinel cache cleared.');
    });
    reg('depSentinel.menu', () => this.showMenu());
    reg('depSentinel.filter', async (id?: FindingFilter) => {
      const filter =
        id ??
        (
          await vscode.window.showQuickPick(
            FILTERS.map((f) => ({ label: `${f.id === this.tree.filter ? '$(check) ' : ''}${f.label}`, detail: f.detail, id: f.id })),
            { title: 'Filter DepSentinel findings' },
          )
        )?.id;
      if (!filter) return;
      await this.context.workspaceState.update(STATE_FILTER, filter);
      this.applyFilter(filter);
    });
    reg('depSentinel.clearFilter', () => vscode.commands.executeCommand('depSentinel.filter', 'all'));
    reg('depSentinel.pause', () => this.setPaused(true));
    reg('depSentinel.resume', () => this.setPaused(false));
    reg('depSentinel.exportReport', (format?: 'markdown' | 'sarif' | 'json', target?: vscode.Uri) => this.exportReport(format, target));
    reg('depSentinel.openSettings', () => vscode.commands.executeCommand('workbench.action.openSettings', `@ext:${this.context.extension.id}`));
    reg('depSentinel.gettingStarted', () =>
      vscode.commands.executeCommand('workbench.action.openWalkthrough', `${this.context.extension.id}#${WALKTHROUGH}`, false),
    );
    // CodeLens click: put the cursor on the line and open the quick-fix menu.
    reg('depSentinel.lineActions', async (uri: vscode.Uri, line: number) => {
      const editor = await vscode.window.showTextDocument(uri, { preserveFocus: false });
      const pos = new vscode.Position(line, editor.document.lineAt(line).firstNonWhitespaceCharacterIndex);
      editor.selection = new vscode.Selection(pos, pos);
      await vscode.commands.executeCommand('editor.action.quickFix');
    });
  }

  private registerWatchers() {
    const watcher = vscode.workspace.createFileSystemWatcher(MANIFEST_GLOB);
    const excludedDirs = this.excludedDirNames();
    const onChange = (uri: vscode.Uri) => {
      if (this.paused || !cfg().get('scanOnChange', true)) return;
      const segments = uri.fsPath.split(/[\\/]/);
      if (segments.some((s) => excludedDirs.has(s))) return;
      this.pendingFiles.add(path.dirname(uri.fsPath));
      if (this.changeTimer) clearTimeout(this.changeTimer);
      this.changeTimer = setTimeout(() => void this.scanChanged(), 2500);
    };
    watcher.onDidChange(onChange);
    watcher.onDidCreate(onChange);
    watcher.onDidDelete(onChange);
    this.disposables.push(
      watcher,
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (!e.affectsConfiguration(SECTION)) return;
        if (e.affectsConfiguration(`${SECTION}.npmRegistry`) || e.affectsConfiguration(`${SECTION}.mavenRepositories`)) this.warnConfigProblems();
        if (e.affectsConfiguration(`${SECTION}.scanIntervalMinutes`)) this.schedule();
        if (e.affectsConfiguration(`${SECTION}.codeLens`)) this.codeLens.refresh();
        const uiOnly = ['notifications', 'scanOnChange', 'scanOnStartup', 'codeLens', 'scanIntervalMinutes'];
        if (uiOnly.some((k) => e.affectsConfiguration(`${SECTION}.${k}`))) return;
        void this.scanAll('settings');
      }),
      vscode.workspace.onDidChangeWorkspaceFolders(() => void this.scanAll('workspace')),
    );
  }

  private excludedDirNames(): Set<string> {
    const glob = cfg().get<string>('exclude', '');
    const m = /\{([^}]+)\}/.exec(glob);
    return new Set(['node_modules', '.git', ...(m ? m[1].split(',').map((s) => s.trim()) : [])]);
  }

  private async discover(): Promise<string[]> {
    const exclude = cfg().get<string>('exclude') || undefined;
    const uris = await vscode.workspace.findFiles(MANIFEST_GLOB, exclude, 5000);
    return discoverScanTargets(
      uris.map((u) => u.fsPath),
      (p) => readTextFile(p, (m) => this.log.warn(m)),
    );
  }

  private coreContext(): CoreContext {
    return {
      config: readCoreConfig(),
      cache: this.cache,
      http: this.http,
      log: this.log,
      readFile: (p) => readTextFile(p, (m) => this.log.warn(m)),
      allowedRoots: (vscode.workspace.workspaceFolders ?? []).filter((f) => f.uri.scheme === 'file').map((f) => f.uri.fsPath),
      isCancelled: () => this.cancelRequested,
    };
  }

  async scanAll(reason: string) {
    if (this.scanning) {
      this.pendingFull = true;
      return;
    }
    if (!vscode.workspace.workspaceFolders?.length) return;
    const targets = await this.discover();
    this.noManifests = targets.length === 0;
    if (this.noManifests) {
      for (const file of [...this.results.keys()]) this.diagnostics.remove(file);
      this.results.clear();
      this.lastScan = new Date();
      this.schedule();
      this.refreshUi();
      if (reason === 'manual') vscode.window.showInformationMessage('DepSentinel: no supported manifests or lockfiles found in this workspace.');
      return;
    }
    await this.runScan(targets, reason, true);
  }

  private async scanChanged() {
    const dirs = new Set(this.pendingFiles);
    this.pendingFiles.clear();
    if (this.scanning) {
      dirs.forEach((d) => this.pendingFiles.add(d));
      return;
    }
    const all = await this.discover();
    const targets = all.filter((t) => dirs.has(path.dirname(t)));
    // Remove results of files that are no longer scan targets in those dirs.
    for (const file of [...this.results.keys()]) {
      if (dirs.has(path.dirname(file)) && !all.includes(file)) {
        this.results.delete(file);
        this.diagnostics.remove(file);
      }
    }
    if (targets.length) await this.runScan(targets, 'file change', false);
    else this.refreshUi();
  }

  private async runScan(targets: string[], reason: string, full: boolean) {
    this.scanning = true;
    this.cancelRequested = false;
    this.lastError = undefined;
    this.refreshUi();
    this.log.info(`Scan started (${reason}) – ${targets.length} manifest(s)`);
    const manual = reason === 'manual';
    const before = issueIds([...this.results.values()]);
    const known = new Set(this.context.workspaceState.get<string[]>(STATE_KNOWN, [...before]));

    try {
      const results = await vscode.window.withProgress(
        {
          location: manual ? vscode.ProgressLocation.Notification : vscode.ProgressLocation.Window,
          title: 'DepSentinel',
          cancellable: manual,
        },
        async (progress, token) => {
          token.onCancellationRequested(() => (this.cancelRequested = true));
          this.progressPct = 0;
          this.progressMsg = 'Starting…';
          return new Scanner(this.coreContext()).scan(targets, (message, fraction) => {
            const pct = fraction === undefined ? this.progressPct : Math.round(fraction * 100);
            progress.report({ message: `${pct}% · ${message}`, increment: Math.max(0, pct - this.progressPct) });
            this.progressPct = pct;
            this.progressMsg = message;
            // Per-package updates arrive in bursts: refresh the status bar and tree at most 4x a second.
            if (Date.now() - this.lastProgressUi > 250) {
              this.lastProgressUi = Date.now();
              this.refreshUi();
            }
          });
        },
      );

      if (full) {
        for (const file of [...this.results.keys()]) {
          if (!targets.includes(file)) {
            this.results.delete(file);
            this.diagnostics.remove(file);
          }
        }
      }
      for (const r of results) {
        this.results.set(r.file, r);
        await this.diagnostics.update(r);
        r.warnings.forEach((w) => this.log.warn(`${r.file}: ${w}`));
      }
      if (full) {
        this.lastScan = new Date();
        await this.context.workspaceState.update(STATE_LAST_SCAN, this.lastScan.toISOString());
      }
      await this.context.workspaceState.update(STATE_RESULTS, [...this.results.values()]);
      await this.context.workspaceState.update(STATE_RESULTS_FORMAT, RESULTS_FORMAT);

      const after = issueIds([...this.results.values()]);
      const fresh = [...after].filter((id) => !known.has(id));
      await this.context.workspaceState.update(STATE_KNOWN, [...after]);
      this.notify(fresh, manual);
      this.log.info(`Scan finished: ${after.size} issue(s), ${fresh.length} new`);
    } catch (e) {
      this.lastError = (e as Error).message;
      this.log.error(`Scan failed: ${(e as Error).stack ?? e}`);
      if (manual) vscode.window.showErrorMessage(`DepSentinel scan failed: ${(e as Error).message}`, 'Show Log').then((p) => p && this.output.show());
    } finally {
      this.scanning = false;
      this.refreshUi();
      // Retry sooner when a full scan failed (usually offline), otherwise wait a full interval.
      if (full) this.schedule(this.lastError ? Math.min(OFFLINE_RETRY_MS, this.intervalMs()) : this.intervalMs());
      if (this.pendingFull) {
        this.pendingFull = false;
        void this.scanAll('queued');
      } else if (this.pendingFiles.size) {
        void this.scanChanged();
      }
    }
  }

  private notify(freshIds: string[], manual: boolean) {
    const mode = cfg().get<'new' | 'all' | 'off'>('notifications', 'new');
    if (mode === 'off') return;
    const findings = [...this.results.values()].flatMap((r) => r.findings.map((f) => ({ r, f })));
    const freshSet = new Set(freshIds);
    const relevant = mode === 'all' || manual ? findings : findings.filter(({ r, f }) => [...f.vulns.map((v) => `${r.file}|${f.key}|${v.id}`), `${r.file}|${f.key}|suspicious`].some((id) => freshSet.has(id)));
    if (!relevant.length) {
      if (manual) vscode.window.showInformationMessage('DepSentinel: no known vulnerabilities or suspicious packages found. ✅');
      return;
    }
    const vulns = relevant.flatMap(({ f }) => f.vulns);
    const count = (s: string) => vulns.filter((v) => v.severity === s).length;
    const malicious = relevant.filter(({ f }) => f.vulns.some((v) => v.isMalicious));
    const suspicious = relevant.filter(({ f }) => f.suspicious);
    const sevParts = ['critical', 'high', 'medium', 'low'].map((s) => (count(s) ? `${count(s)} ${s}` : '')).filter(Boolean);
    const pieces: string[] = [];
    if (malicious.length) pieces.push(`☠ ${malicious.length} MALICIOUS package(s): ${malicious.slice(0, 3).map(({ f }) => `${f.name}@${f.version}`).join(', ')}`);
    if (vulns.length) pieces.push(`${vulns.length} ${mode === 'new' && !manual ? 'new ' : ''}vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} (${sevParts.join(', ')})`);
    if (suspicious.length) pieces.push(`${suspicious.length} suspicious package(s): ${suspicious.slice(0, 3).map(({ f }) => `${f.name}@${f.version}`).join(', ')}`);
    const msg = `DepSentinel: ${pieces.join(' · ')}`;
    const show = malicious.length || count('critical') || count('high') ? vscode.window.showErrorMessage : vscode.window.showWarningMessage;
    show(msg, 'Show Findings', 'Open Report').then((pick) => {
      if (pick === 'Show Findings') void vscode.commands.executeCommand('depSentinel.findings.focus');
      if (pick === 'Open Report') void vscode.commands.executeCommand('depSentinel.showReport');
    });
  }

  private refreshUi() {
    const results = [...this.results.values()].sort((a, b) => a.file.localeCompare(b.file));
    const findings = results.flatMap((r) => r.findings);
    const vulns = findings.flatMap((f) => f.vulns);
    const crit = vulns.filter((v) => v.severity === 'critical').length;
    const high = vulns.filter((v) => v.severity === 'high').length;
    const sus = findings.filter((f) => f.suspicious).length;
    const malicious = findings.filter((f) => f.vulns.some((v) => v.isMalicious)).length;
    const packages = results.reduce((n, r) => n + r.packageCount, 0);
    const when = this.lastScan ? this.lastScan.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'never';

    let state: SummaryState = vulns.length || sus ? 'issues' : this.lastScan ? 'ok' : 'idle';
    if (this.noManifests) state = 'empty';
    if (this.lastError) state = 'error';
    if (this.paused) state = 'paused';
    if (this.scanning) state = 'scanning';

    const labels: Record<SummaryState, string> = {
      scanning: `Scanning dependencies… ${this.progressPct}%`,
      error: `Last scan failed: ${this.lastError}`,
      paused: 'Monitoring paused',
      empty: 'No supported manifests found',
      idle: 'Not scanned yet',
      ok: `Last scan ${when}`,
      issues: `Last scan ${when}`,
    };
    const detail =
      state === 'scanning'
        ? this.progressMsg
        : state === 'empty'
        ? 'package.json, pom.xml, lockfiles, requirements.txt, go.mod…'
        : state === 'paused'
          ? 'click the status bar to resume'
          : `${packages} pkgs · ${vulns.length} vulns${sus ? ` · ${sus} suspicious` : ''}`;
    this.tree.set(results, { kind: 'summary', label: labels[state], detail, state }, this.suppressionNotes());

    const projects = groupProjects(results, workspaceRoots());
    if (this.scanning) {
      this.status.text = `$(sync~spin) DepSentinel: ${this.progressPct}%`;
    } else if (this.paused) {
      this.status.text = '$(debug-pause) DepSentinel: paused';
    } else if (malicious) {
      this.status.text = `$(bug) DepSentinel: ${malicious} malicious`;
    } else if (vulns.length || sus) {
      this.status.text = `$(shield) DepSentinel: ${[crit && `${crit} critical`, high && `${high} high`, `${vulns.length} vulns`].filter(Boolean).join(' · ')}${sus ? ` · ${sus} ⚠` : ''}`;
    } else if (this.lastError) {
      this.status.text = '$(warning) DepSentinel: scan failed';
    } else {
      this.status.text = this.lastScan && !this.noManifests ? '$(shield) DepSentinel: secure' : '$(shield) DepSentinel';
    }
    this.status.backgroundColor = malicious || crit ? new vscode.ThemeColor('statusBarItem.errorBackground') : high || sus ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
    // Hover card with clickable controls. Only our own commands are enabled; project names are escaped.
    const tip = new vscode.MarkdownString('', true);
    tip.isTrusted = {
      enabledCommands: ['depSentinel.scanNow', 'depSentinel.showReport', 'depSentinel.findings.focus', 'depSentinel.pause', 'depSentinel.resume', 'depSentinel.openSettings', 'depSentinel.menu'],
    };
    tip.appendMarkdown(`**$(shield) DepSentinel**${this.paused ? ' — paused' : ''}\n\n`);
    tip.appendMarkdown(
      [
        `Last scan: ${this.lastScan ? `${this.lastScan.toLocaleString()} (${relative(this.lastScan)})` : 'never'}`,
        `${packages} packages checked in ${projects.length} project${projects.length === 1 ? '' : 's'} (incl. sub-dependencies)`,
        `${vulns.length} vulnerabilities — ${crit} critical, ${high} high · ${sus} suspicious · ${malicious} malicious`,
        this.paused ? 'Automatic checks are paused' : `Next check: ${Number.isFinite(this.nextDue) ? relative(new Date(this.nextDue)) : 'after the first scan'}`,
      ].join('  \n') + '\n\n',
    );
    if (projects.length > 1) {
      for (const p of projects.slice(0, 8)) {
        const s = statsOf(p.results);
        const icon = s.malicious || s.critical || s.high ? '$(error)' : s.affected ? '$(warning)' : '$(pass)';
        tip.appendMarkdown(`${icon} `).appendText(p.name).appendMarkdown(` — ${p.ecosystem}, ${s.vulns ? `${s.vulns} vulns` : 'clean'}${s.suspicious ? `, ${s.suspicious} suspicious` : ''}  \n`);
      }
      if (projects.length > 8) tip.appendMarkdown(`…and ${projects.length - 8} more  \n`);
      tip.appendMarkdown('\n');
    }
    tip.appendMarkdown('---\n\n');
    tip.appendMarkdown(
      [
        '[$(refresh) Scan now](command:depSentinel.scanNow)',
        '[$(preview) Report](command:depSentinel.showReport)',
        '[$(list-tree) Findings](command:depSentinel.findings.focus)',
        this.paused ? '[$(debug-start) Resume](command:depSentinel.resume)' : '[$(debug-pause) Pause](command:depSentinel.pause)',
        '[$(gear) Settings](command:depSentinel.openSettings)',
      ].join(' &nbsp;·&nbsp; '),
    );
    this.status.tooltip = tip;
    const affected = findings.filter((f) => f.vulns.length || f.suspicious).length;
    if (this.view) this.view.badge = affected ? { value: affected, tooltip: `${affected} affected package(s)` } : undefined;
    refreshReport(results, this.lastScan);
  }

  dispose() {
    if (this.ticker) clearInterval(this.ticker);
    if (this.changeTimer) clearTimeout(this.changeTimer);
    this.cancelRequested = true;
    void this.cache.flush();
    this.disposables.forEach((d) => d.dispose());
  }
}
