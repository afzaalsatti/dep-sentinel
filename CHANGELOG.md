# Changelog

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
