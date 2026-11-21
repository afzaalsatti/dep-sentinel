import * as path from 'path';

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Find the (0-based) line of a package declaration in a manifest or lockfile. */
export function locatePackage(fileText: string, file: string, name: string, version?: string): number | undefined {
  const base = path.basename(file).toLowerCase();
  const n = esc(name);
  const patterns: RegExp[] = [];
  switch (true) {
    case base === 'package.json':
    case base === 'composer.json':
      patterns.push(new RegExp(`"${n}"\\s*:`));
      break;
    case base === 'package-lock.json' || base === 'npm-shrinkwrap.json':
      patterns.push(new RegExp(`"node_modules/${n}"\\s*:`), new RegExp(`"${n}"\\s*:\\s*\\{`));
      break;
    case base === 'yarn.lock':
      patterns.push(new RegExp(`^"?${n}@`, 'm'));
      break;
    case base === 'pnpm-lock.yaml':
      patterns.push(new RegExp(`^\\s+'?/?${n}[@/]${version ? esc(version) : ''}`, 'm'), new RegExp(`^\\s+'?${n}'?:`, 'm'));
      break;
    case base === 'pom.xml' || base.endsWith('.gradle') || base.endsWith('.kts') || base === 'libs.versions.toml' || base === 'gradle.lockfile': {
      const [g, a] = name.split(':');
      patterns.push(new RegExp(`<artifactId>\\s*${esc(a ?? name)}\\s*</artifactId>`), new RegExp(`${esc(g)}:${esc(a ?? '')}`), new RegExp(`["']${esc(a ?? name)}["']`));
      break;
    }
    case /requirements.*\.txt$/.test(base): {
      const loose = name.split(/[-_.]/).map(esc).join('[-_.]');
      patterns.push(new RegExp(`^\\s*${loose}\\s*(\\[|=|~|>|<|!|;|$)`, 'im'));
      break;
    }
    case base === 'go.mod':
      patterns.push(new RegExp(`^\\s*(require\\s+)?${n}\\s+v`, 'm'));
      break;
    case base.endsWith('.lock') || base === 'pipfile' || base === 'pyproject.toml' || base === 'cargo.toml':
      patterns.push(new RegExp(`name\\s*=\\s*"${n}"`, 'i'), new RegExp(`^\\s*"?${n}"?\\s*[=(]`, 'im'), new RegExp(`^\\s+${n} \\(`, 'm'));
      break;
    case base.endsWith('proj') || base.endsWith('.props'):
      patterns.push(new RegExp(`Include="${n}"`, 'i'));
      break;
    case base === 'packages.lock.json':
      patterns.push(new RegExp(`"${n}"\\s*:`, 'i'));
      break;
  }
  patterns.push(new RegExp(n));
  for (const re of patterns) {
    const m = re.exec(fileText);
    if (m) return lineOf(fileText, m.index);
  }
  return undefined;
}

function lineOf(text: string, index: number): number {
  let line = 0;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}
