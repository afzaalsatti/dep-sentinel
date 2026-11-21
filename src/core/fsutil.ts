import { promises as fs } from 'fs';

/** Largest manifest/lockfile we are willing to read (real-world lockfiles are a few MB at most). */
export const MAX_MANIFEST_BYTES = 32 * 1024 * 1024;

/**
 * Read a text file with a size cap. Returns undefined when the file is missing, not a regular file, or too large,
 * so a hostile repository cannot exhaust memory with a giant "lockfile" or a FIFO/device path.
 */
export async function readTextFile(file: string, onSkip?: (reason: string) => void, maxBytes = MAX_MANIFEST_BYTES): Promise<string | undefined> {
  try {
    const st = await fs.stat(file);
    if (!st.isFile()) return undefined;
    if (st.size > maxBytes) {
      onSkip?.(`${file} skipped: ${(st.size / 1048576).toFixed(1)} MB exceeds the ${(maxBytes / 1048576).toFixed(1)} MB limit`);
      return undefined;
    }
    return await fs.readFile(file, 'utf8');
  } catch {
    return undefined;
  }
}
