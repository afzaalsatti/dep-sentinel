import * as path from 'path';
import { modify, parseTree, findNodeAtLocation } from 'jsonc-parser';

/** Offset-based text edit (start offset, length to replace, replacement). */
export interface OffsetEdit {
  offset: number;
  length: number;
  content: string;
}

export interface OverridePlan {
  edits: OffsetEdit[];
  /** Human-readable description of what is written, e.g. `overrides["qs@6.7.0"] = "6.7.3"`. */
  description: string;
}

function detectIndent(text: string): { insertSpaces: boolean; tabSize: number } {
  const m = /\n([ \t]+)\S/.exec(text);
  if (!m) return { insertSpaces: true, tabSize: 2 };
  return m[1].startsWith('\t') ? { insertSpaces: false, tabSize: 1 } : { insertSpaces: true, tabSize: m[1].length };
}

/**
 * Plan a package.json edit that forces a transitive dependency to a fixed version.
 * npm and pnpm support version selectors, so only the vulnerable version is replaced (`qs@6.7.0 → 6.7.3`) and
 * other copies of the package in the tree are left alone. Yarn's `resolutions` has no selector and applies to all copies.
 */
export function planNpmOverride(packageJsonText: string, lockfile: string, name: string, current: string, target: string): OverridePlan | undefined {
  const lock = path.basename(lockfile);
  let jsonPath: string[];
  if (lock === 'package-lock.json' || lock === 'npm-shrinkwrap.json' || lock === 'package.json') jsonPath = ['overrides', `${name}@${current}`];
  else if (lock === 'pnpm-lock.yaml') jsonPath = ['pnpm', 'overrides', `${name}@${current}`];
  else if (lock === 'yarn.lock') jsonPath = ['resolutions', name];
  else return undefined;

  const tree = parseTree(packageJsonText);
  if (!tree || tree.type !== 'object') return undefined;
  // Don't clobber a hand-written override for the same package.
  const parent = findNodeAtLocation(tree, jsonPath.slice(0, -1));
  if (parent?.type === 'object' && parent.children?.some((p) => {
    const key = p.children?.[0]?.value;
    return typeof key === 'string' && (key === name || key.startsWith(`${name}@`));
  })) {
    return undefined;
  }
  const edits = modify(packageJsonText, jsonPath, target, { formattingOptions: { ...detectIndent(packageJsonText), eol: packageJsonText.includes('\r\n') ? '\r\n' : '\n' } });
  if (!edits.length) return undefined;
  return { edits, description: `${jsonPath.slice(0, -1).join('.')}["${jsonPath[jsonPath.length - 1]}"] = "${target}"` };
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Plan a pom.xml edit that pins a transitive artifact via <dependencyManagement>
 * (Maven applies the root's managed versions to transitive dependencies).
 */
export function planMavenPin(pomText: string, ga: string, target: string): OverridePlan | undefined {
  const [g, a] = ga.split(':');
  if (!g || !a) return undefined;
  const eol = pomText.includes('\r\n') ? '\r\n' : '\n';
  const unit = /\n([ \t]+)</.exec(pomText)?.[1] ?? '  ';
  const ind = (n: number) => unit.repeat(n);
  const dep = (level: number) =>
    [
      `${ind(level)}<dependency>`,
      `${ind(level + 1)}<groupId>${g}</groupId>`,
      `${ind(level + 1)}<artifactId>${a}</artifactId>`,
      `${ind(level + 1)}<version>${target}</version>`,
      `${ind(level)}</dependency>`,
    ].join(eol);

  const dm = /<dependencyManagement>\s*<dependencies>/.exec(pomText);
  if (dm) {
    const end = pomText.indexOf('</dependencyManagement>', dm.index);
    const block = pomText.slice(dm.index, end < 0 ? undefined : end);
    if (new RegExp(`<groupId>\\s*${esc(g)}\\s*</groupId>\\s*<artifactId>\\s*${esc(a)}\\s*</artifactId>`).test(block)) return undefined; // already managed
    const offset = dm.index + dm[0].length;
    return { edits: [{ offset, length: 0, content: eol + dep(3) }], description: `<dependencyManagement> pin ${ga}:${target}` };
  }

  const block = [`${ind(1)}<dependencyManagement>`, `${ind(2)}<dependencies>`, dep(3), `${ind(2)}</dependencies>`, `${ind(1)}</dependencyManagement>`].join(eol) + eol;
  // Insert before the project-level <dependencies> (one indentation level deep), else before </project>.
  const top = new RegExp(`(^|\\n)${esc(unit)}<dependencies>`).exec(pomText);
  if (top) {
    const offset = top.index + (top[1] ? top[1].length : 0);
    return { edits: [{ offset, length: 0, content: block }], description: `<dependencyManagement> pin ${ga}:${target}` };
  }
  const close = pomText.lastIndexOf('</project>');
  if (close < 0) return undefined;
  return { edits: [{ offset: close, length: 0, content: block }], description: `<dependencyManagement> pin ${ga}:${target}` };
}
