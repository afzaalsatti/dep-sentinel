import * as vscode from 'vscode';
import { isAllowedUrl } from './core/http';
import type { CoreConfig, Severity } from './core/types';

export const SECTION = 'depSentinel';

const DEFAULT_MAVEN = 'https://repo1.maven.org/maven2';
const DEFAULT_NPM = 'https://registry.npmjs.org';
const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];

export function cfg() {
  return vscode.workspace.getConfiguration(SECTION);
}

/** Problems found while reading settings (shown to the user once per change). */
export function configProblems(): string[] {
  const c = cfg();
  const problems: string[] = [];
  for (const url of c.get<string[]>('mavenRepositories', [])) {
    if (!isAllowedUrl(url)) problems.push(`Ignoring Maven repository "${url}": only https:// URLs (or http://localhost) are allowed.`);
  }
  const npm = c.get<string>('npmRegistry', DEFAULT_NPM);
  if (!isAllowedUrl(npm)) problems.push(`Ignoring npm registry "${npm}": only https:// URLs (or http://localhost) are allowed. Using ${DEFAULT_NPM}.`);
  return problems;
}

/** Read settings into the core config, dropping unsafe or malformed values. */
export function readCoreConfig(): CoreConfig {
  const c = cfg();
  const strings = (key: string): string[] => (c.get<unknown[]>(key, []) ?? []).filter((x): x is string => typeof x === 'string' && x.trim() !== '');
  const num = (key: string, def: number, min: number, max: number) => {
    const v = Number(c.get(key, def));
    return Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : def;
  };
  const repos = strings('mavenRepositories').filter(isAllowedUrl);
  const npm = c.get<string>('npmRegistry', DEFAULT_NPM);
  const minSev = c.get<Severity>('minimumSeverity', 'low');
  return {
    includeDev: c.get<boolean>('includeDevDependencies', true) !== false,
    resolveTransitive: c.get<boolean>('resolveTransitive', true) !== false,
    maxDepth: num('maxTransitiveDepth', 8, 1, 20),
    mavenRepos: repos.length ? repos : [DEFAULT_MAVEN],
    npmRegistry: isAllowedUrl(npm) ? npm : DEFAULT_NPM,
    ignoredAdvisories: strings('ignoredAdvisories'),
    minimumSeverity: SEVERITIES.includes(minSev) ? minSev : 'low',
    exploitData: c.get<boolean>('exploitData.enabled', true) !== false,
    supplyChain: {
      enabled: c.get<boolean>('supplyChain.enabled', true) !== false,
      recentPublishHours: num('supplyChain.recentPublishHours', 72, 1, 24 * 30),
      threshold: num('supplyChain.suspicionThreshold', 5, 1, 100),
      allowedRegistries: strings('supplyChain.allowedRegistries'),
      trustedPackages: strings('supplyChain.trustedPackages'),
      maxRegistryLookups: num('supplyChain.maxRegistryLookups', 4000, 0, 20000),
    },
  };
}

/**
 * Settings that silence findings. Surfaced in the UI so that suppression is never invisible – a repository could
 * otherwise commit `.vscode/settings.json` that hides its own malicious dependency.
 */
export function suppressionSummary(): { ignored: string[]; trusted: string[]; fromWorkspace: boolean } {
  const c = cfg();
  const i = c.inspect<string[]>('ignoredAdvisories');
  const t = c.inspect<string[]>('supplyChain.trustedPackages');
  const ws = (x: typeof i) => !!(x?.workspaceValue?.length || x?.workspaceFolderValue?.length);
  return {
    ignored: c.get<string[]>('ignoredAdvisories', []),
    trusted: c.get<string[]>('supplyChain.trustedPackages', []),
    fromWorkspace: ws(i) || ws(t),
  };
}

/** Add a value to an array setting, at workspace level when a workspace is open. */
export async function appendToSetting(key: string, value: string) {
  const c = cfg();
  const current = c.get<string[]>(key, []);
  if (current.includes(value)) return;
  const target = vscode.workspace.workspaceFolders?.length ? vscode.ConfigurationTarget.Workspace : vscode.ConfigurationTarget.Global;
  await c.update(key, [...current, value], target);
}
