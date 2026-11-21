import * as path from 'path';

export interface TextEditSpec {
  line: number;
  start: number;
  end: number;
  newText: string;
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Compute the text edit that changes the declared version of `name` to `target`.
 * `line` is the 0-based line where the dependency is declared (as located by locatePackage).
 * Returns undefined when the version cannot be edited safely (git URLs, unresolved variables, managed versions…).
 */
export function computeVersionEdit(text: string, file: string, name: string, line: number, target: string): TextEditSpec | undefined {
  const lines = text.split(/\r?\n/);
  const base = path.basename(file).toLowerCase();
  // All patterns below are written so that capture groups are contiguous from the start of the match.
  const at = (re: RegExp, l: number, group: number): TextEditSpec | undefined => {
    const m = re.exec(lines[l] ?? '');
    if (!m) return undefined;
    const start = m.index + m.slice(1, group).reduce((n, g) => n + (g?.length ?? 0), 0);
    return { line: l, start, end: start + m[group].length, newText: target };
  };

  if (base === 'package.json') {
    // "name": "^1.2.3"  -> keep the range operator
    const re = new RegExp(`("${esc(name)}"\\s*:\\s*")([\\^~]|>=\\s*)?(\\d[^"\\s]*)(")`);
    return at(re, line, 3);
  }
  if (/requirements.*\.txt$/.test(base)) {
    const loose = name.split(/[-_.]/).map(esc).join('[-_.]');
    const re = new RegExp(`^(\\s*${loose}\\s*(?:\\[[^\\]]*\\])?\\s*===?\\s*)([^\\s;#,]+)`, 'i');
    return at(re, line, 2);
  }
  if (base === 'go.mod') {
    const re = new RegExp(`^(\\s*(?:require\\s+)?${esc(name)}\\s+v)(\\S+)`);
    return at(re, line, 2);
  }
  if (base.endsWith('.gradle') || base.endsWith('.gradle.kts')) {
    const [g, a] = name.split(':');
    const re = new RegExp(`(["']${esc(g)}:${esc(a)}:)([^"'$:@\\s]+)`);
    return at(re, line, 2);
  }
  if (base === 'pom.xml') {
    // Search the <dependency> block around the located line for its <version>.
    let startLine = line;
    while (startLine > 0 && !/<dependency>/.test(lines[startLine]) && line - startLine < 10) startLine--;
    for (let l = startLine; l < Math.min(lines.length, startLine + 15); l++) {
      if (l > startLine && /<dependency>/.test(lines[l])) break;
      const m = /(<version>\s*)([^<\s]+)(\s*<\/version>)/.exec(lines[l]);
      if (m) {
        const prop = /^\$\{([^}]+)\}$/.exec(m[2]);
        if (!prop) return { line: l, start: m.index + m[1].length, end: m.index + m[1].length + m[2].length, newText: target };
        // Version comes from a property: edit the property definition instead.
        const re = new RegExp(`(<${esc(prop[1])}>\\s*)([^<\\s]+)(\\s*</${esc(prop[1])}>)`);
        for (let p = 0; p < lines.length; p++) {
          const pm = re.exec(lines[p]);
          if (pm) return { line: p, start: pm.index + pm[1].length, end: pm.index + pm[1].length + pm[2].length, newText: target };
        }
        return undefined;
      }
      if (/<\/dependency>/.test(lines[l])) break;
    }
    return undefined; // version managed by a parent/BOM
  }
  return undefined;
}
