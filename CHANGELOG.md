# Changelog

## 1.0.0
First production release, focused on making DepSentinel itself safe to run on untrusted code.

**Security hardening**
- Fixed **prototype pollution** in the TOML parser (`[__proto__.x]` in a hostile `Cargo.lock`/`pyproject.toml` could pollute `Object.prototype` in the extension host).
- POM parsing no longer expands XML entities (billion laughs). External entities (XXE) are refused. Maven property lookups are own-property only.
- **HTTPS-only networking**, including manual, pre-validated redirects (max 5 hops). No credentials sent. 64 MB response cap. Registry URLs in settings are validated.
- Manifest files are size-capped (32 MB). Only regular files inside the workspace are read; a POM `<relativePath>` can no longer escape it.
- **Restricted Mode:** suppression, registry and threshold settings from untrusted workspaces are ignored. Every suppression is shown in the view and flagged when set by the workspace.
- Advisory links are vetted (http/https only) everywhere. Tooltips escape external text. The report webview disables scripts, forms, command links and local resources. Exports escape HTML.
- The lockfile refresh after a Quick Fix uses lockfile-only commands with `--ignore-scripts`, and is never offered in untrusted workspaces.

**Own supply chain**
- All dependencies pinned exactly. Lockfile regenerated so every package is at least 7 days old. `npm audit`: 0 vulnerabilities (`fast-xml-parser` 5.12.1, `esbuild` 0.28.2, `@vscode/vsce` 4.1.1, `minimatch` override 11.0.8).
- `.npmrc` blocks dependency install scripts. VSIX ships only the bundle and media. SHA-256 checksum generated on package.
- CI: SHA-pinned actions, least-privilege permissions, typecheck/tests/audit, DepSentinel self-scan gate, weekly runs, SARIF to code scanning. Dependabot with a 7-day cooldown.
- `SECURITY.md` with threat model, data handling, dependency policy and private reporting.

**Accuracy**
- Typosquat: scoped npm packages are no longer judged by their bare name (`@secretlint/core` ≠ `core-js`); `core` no longer matches `core-js`.
- Publisher change: an account on the same organisation e-mail domain as a previous maintainer is not flagged (public mail domains excluded).

**Licensing**
- Released under the MIT License (`LICENSE` is included in the VSIX).

**Polish**
- Build toolchain pinned to Node.js 22 LTS via `.nvmrc` (used by CI). The CLI still runs on Node.js 18.18 or later.
- CLI: `--exclude`, `--trust`. Stricter TypeScript (`noUnused*`, `noImplicitReturns`, …). Compiled against the VS Code 1.90 API to guarantee the declared minimum. `.gitattributes` for consistent line endings.

## 0.4.0
- **New icon:** a shield guarding a dependency tree, with one vulnerable node. 256 px marketplace icon and a matching monochrome Activity Bar icon.
- **Getting Started walkthrough** (Welcome page) with six interactive steps: scan, findings, fixes, supply-chain warnings, settings, sharing/CI.
- **CodeLens** above every affected dependency line: vulnerability count, worst severity, recommended fix, vulnerable sub-dependencies, malicious warning. Click it for quick fixes.
- **Status-bar menu:** scan, findings, report, export, filter, pause/resume, settings, help. The tooltip shows the last and next check.
- **Filter findings:** critical & high, supply-chain risks, direct only, or hide dev dependencies. Shown in the view title and remembered per workspace.
- **Pause / resume monitoring** per workspace.
- **Export report** as Markdown (for PRs, tickets, chat), SARIF 2.1.0 or JSON. The CLI gains `--markdown`.
- **Better empty and welcome states:** explains what DepSentinel does, "no supported manifests found", "all manifests are clean", "nothing matches the filter".
- Inline actions in the tree (open advisory, reveal in manifest), command categories, one-time welcome hint after install.

## 0.3.0
- **Quick Fix for transitive dependencies:** npm `overrides` with a version selector (only the vulnerable copy is replaced), `pnpm.overrides`, Yarn `resolutions`, and Maven `<dependencyManagement>` pins.
- **Same-major vs. major recommendations:** the preferred Quick Fix stays on your major line ("fixes 24 of 37"). The upgrade that fixes everything is offered separately and labelled ⚠ major version.
- **Only installable versions are recommended:** fixed versions that were never publicly released (e.g. commercial-only Spring 5.3.4x) are skipped.
- The npm registry resolver (no-lockfile mode) now honours `overrides`, `pnpm.overrides` and `resolutions`.
- **New CLI** (`dist/cli.js`) for CI: human output, JSON, SARIF 2.1.0 for GitHub code scanning, `--fail-on` exit codes.
- Marketplace icon.
- Fixed: the bundled extension failed to load `jsonc-parser` (UMD build). It now bundles the ES module build.

## 0.2.0
- **Fix recommendations:** each vulnerable package shows the lowest version that fixes all its advisories (branch-aware, e.g. log4j 2.14.1 → 2.17.1, Spring 5.3.7 → 5.3.18 rather than a 5.2.x backport).
- **Quick Fix (💡):** one-click upgrade in `package.json`, `pom.xml` (including `${property}` versions), `requirements.txt`, Gradle and `go.mod`. It also offers to refresh the lockfile, which only runs when you click it.
- Quick actions to open or ignore an advisory directly from the Problems panel or the editor.
- Activity-bar badge with the number of affected packages.
- The scheduler survives sleep/hibernate and retries after 5 minutes when offline.
- Bundled with esbuild: smaller package and faster activation.
- Supports untrusted workspaces (only reads text, never runs project code).
- Faster diagnostics: each file is read once per update.

## 0.1.0
- Initial release: hourly OSV/CVE checks across npm, Maven, Gradle, PyPI, Go, Cargo, RubyGems, Packagist and NuGet, including transitive dependencies, plus supply-chain risk detection.
