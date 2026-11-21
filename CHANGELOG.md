# Changelog

## 1.1.1
The first published release of the 1.1 line (1.1.0 was never published to the Marketplace).

- **New icon:** a dependency grid with one flagged package, matching the website. The activity bar uses a matching single-color version.
- **Website:** [afzaalsatti.github.io/dep-sentinel](https://afzaalsatti.github.io/dep-sentinel/), linked from the README.
- README: the Marketplace version badge now uses vsmarketplacebadges.dev; shields.io retired its Visual Studio Marketplace badges, which showed "retired badge".
- **Status bar control:** the DepSentinel item now sits on the right side of the status bar and always reads "DepSentinel: …". Hover over it for a summary of each project with clickable **Scan now · Report · Findings · Pause/Resume · Settings** buttons. Click it for the full action menu, which now lists every project and its status and includes Clear cache.
- **Easier-to-read report:** a plain-language verdict at the top, colored severity tiles, a projects overview with links, and one collapsible section per project. Each affected package is a card that leads with what to do (upgrade to X, remove now, no fix yet), followed by its advisories. Supply-chain signals and long advisory lists are collapsed. A footer explains what each severity means.
- **Prioritize fixes in the report:** every affected package gets a priority (**Fix now / Fix soon / Plan / Later**) with the reasons behind it. The priority weighs severity and CVSS, whether the package ships with the app or is dev tooling only, direct vs sub-dependency, and how easy the fix is. A **Start here** box lists the top three. A sticky toolbar adds search (press `/`), **group by** (project, priority, fix type, dependency to update, severity, or none), **sort by** (priority, easiest fix first, CVSS, severity, most advisories, name), and filters (priority, severity tiles, has a fix, direct only, hide dev-only, compact view). Your choices are kept while the report is open. Each package has an **Open in file** button, and each advisory has an **Ignore** button that asks before ignoring. Scan again and Export are in the header. The report now runs one nonce-locked inline script; command links and forms stay disabled.
- **Real-world exploit data:** advisories are checked against CISA's **Known Exploited Vulnerabilities** catalog and **FIRST EPSS** (the chance of exploitation in the next 30 days). An exploited CVE goes to **Fix now** (**Fix soon** if it is in dev tooling only) and ranks above unexploited critical CVEs. An EPSS of 10% or more raises a finding one priority step; a low EPSS never lowers it. You see this as **🔥 Exploited** / **EPSS** badges in the report (with a "🔥 Exploited or likely" filter and an "Exploit activity" sort), in the Findings view and its tooltips, in Problems, in CLI output, as a "fix first" section and Priority column in the Markdown export, and as `known-exploited` tags with `kev`/`epss` properties in SARIF. Data is cached (KEV 12 h, EPSS 24 h); when offline, the last KEV copy is used and the scan carries on without it. Only public CVE ids are sent (to api.first.org). Turn it off with `depSentinel.exploitData.enabled` or the CLI flag `--no-exploit-data`.
- **Multiple projects in one folder:** results are grouped by project, both in the report and in the Findings view (for example a Java API next to a React app, or the same folder opened as a multi-root workspace). Maven modules and Gradle sub-projects stay with their parent build.
- Fixed: after an update, the results saved by the previous version were shown until the next scheduled scan, so new data (like exploit activity) did not appear for hours. The extension now re-scans at startup when the saved results come from an older version.
- Fixed: a `package.json` in a subfolder was skipped whenever a parent folder had a lockfile, even if it was a separate project. It is now folded into the parent lockfile only when the parent declares it as a workspace (`workspaces` in package.json or `pnpm-workspace.yaml`). This also applies to the CLI.

## 1.0.1
- README: install from the Visual Studio Code Marketplace (Extensions view, Marketplace link, `code --install-extension afzaalshoukat.dep-sentinel`) instead of sideloading a `.vsix`. States the minimum VS Code version. Adds a Marketplace badge.
- README is now user-focused: build/test instructions moved to `CONTRIBUTING.md`, and the CLI guide moved to `docs/cli.md`.
- Walkthrough "Share" step no longer claims the extension ships the CLI; it links to the CLI guide instead (and drops the deprecated CodeQL v3 example).

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
