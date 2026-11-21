import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runTests } from '@vscode/test-electron';

/**
 * Fixture manifests are stored as `<name>.fixture` so that GitHub's dependency graph, Dependabot and other
 * scanners don't treat these intentionally vulnerable/malicious files as real dependencies of this repository.
 * Restore the real file names in the temporary copy the tests run against.
 */
async function restoreFixtureNames(dir: string): Promise<number> {
  let restored = 0;
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) restored += await restoreFixtureNames(full);
    else if (entry.isFile() && entry.name.endsWith('.fixture')) {
      await fs.rename(full, full.slice(0, -'.fixture'.length));
      restored++;
    }
  }
  return restored;
}

async function main() {
  const root = path.resolve(__dirname, '../..');
  // Work on a copy – the tests modify files to exercise the watcher.
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), 'depsentinel-ws-'));
  await fs.cp(path.join(root, 'test-fixtures', 'workspace'), workspace, { recursive: true });
  if ((await restoreFixtureNames(workspace)) === 0) throw new Error('No *.fixture manifests found in test-fixtures/workspace');
  const userData = await fs.mkdtemp(path.join(os.tmpdir(), 'depsentinel-ud-'));
  try {
    await runTests({
      extensionDevelopmentPath: root,
      extensionTestsPath: path.join(__dirname, 'suite'),
      launchArgs: [workspace, '--disable-extensions', '--disable-workspace-trust', `--user-data-dir=${userData}`],
    });
  } catch (e) {
    console.error('Integration tests failed', e);
    process.exitCode = 1; // not process.exit(): that would skip the cleanup below
  } finally {
    for (const dir of [workspace, userData]) {
      await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 }).catch(() => undefined);
    }
  }
}

void main();
