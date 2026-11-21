import * as vscode from 'vscode';
import type { CoreConfig, Severity } from './core/types';

export const SECTION = 'depSentinel';

export function cfg() {
  return vscode.workspace.getConfiguration(SECTION);
}

export function readCoreConfig(): CoreConfig {
  const c = cfg();
  return {
    includeDev: c.get('includeDevDependencies', true),
    resolveTransitive: c.get('resolveTransitive', true),
    maxDepth: c.get('maxTransitiveDepth', 8),
    mavenRepos: c.get('mavenRepositories', ['https://repo1.maven.org/maven2']),
    npmRegistry: c.get('npmRegistry', 'https://registry.npmjs.org'),
    ignoredAdvisories: c.get('ignoredAdvisories', []),
    minimumSeverity: c.get<Severity>('minimumSeverity', 'low'),
    supplyChain: {
      enabled: c.get('supplyChain.enabled', true),
      recentPublishHours: c.get('supplyChain.recentPublishHours', 72),
      threshold: c.get('supplyChain.suspicionThreshold', 5),
      allowedRegistries: c.get('supplyChain.allowedRegistries', []),
      trustedPackages: c.get('supplyChain.trustedPackages', []),
      maxRegistryLookups: c.get('supplyChain.maxRegistryLookups', 4000),
    },
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
