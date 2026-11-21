// Writes <package>.vsix.sha256 next to every built VSIX so downloads can be verified:
//   sha256sum -c dep-sentinel-1.0.0.vsix.sha256          (Linux/macOS)
//   Get-FileHash dep-sentinel-1.0.0.vsix -Algorithm SHA256   (Windows)
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const files = fs.readdirSync(root).filter((f) => f.endsWith('.vsix'));
if (!files.length) {
  console.error('No .vsix found – run "npm run package" first.');
  process.exit(1);
}
for (const f of files) {
  const hash = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, f))).digest('hex');
  fs.writeFileSync(path.join(root, `${f}.sha256`), `${hash}  ${f}\n`);
  console.log(`${hash}  ${f}`);
}
