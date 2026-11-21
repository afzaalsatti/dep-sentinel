import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main() {
  const root = path.resolve(__dirname, '../..');
  // Work on a copy – the tests modify files to exercise the watcher.
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), 'depsentinel-ws-'));
  await fs.cp(path.join(root, 'test-fixtures', 'workspace'), workspace, { recursive: true });
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
