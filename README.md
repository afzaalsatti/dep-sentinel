<p align="center"><img src="media/icon.png" width="112" alt="DepSentinel"></p>

# DepSentinel – Dependency CVE & Supply-Chain Monitor

[![Visual Studio Marketplace](https://vsmarketplacebadges.dev/version-short/afzaalshoukat.dep-sentinel.svg?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=afzaalshoukat.dep-sentinel) [![CI](https://github.com/afzaalsatti/dep-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/afzaalsatti/dep-sentinel/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Website](https://img.shields.io/badge/website-depsentinel-F3F1EB?labelColor=17160F)](https://afzaalsatti.github.io/dep-sentinel/)

**Website:** [afzaalsatti.github.io/dep-sentinel](https://afzaalsatti.github.io/dep-sentinel/), with animated walkthroughs of how dependency attacks work and how DepSentinel catches them.

A VS Code extension that watches every dependency in your workspace – **including sub-dependencies** – and alerts you
when a published CVE/advisory affects you, or when a package looks like a **supply-chain attack**, before you'd otherwise notice.

## How to use (2-minute quick start)

1. **Install** from the [Visual Studio Code Marketplace](https://marketplace.visualstudio.com/items?itemName=afzaalshoukat.dep-sentinel):
   open the Extensions view (`Ctrl+Shift+X` / `Cmd+Shift+X`), search for **DepSentinel**, and click **Install**.
   Or from a terminal: `code --install-extension afzaalshoukat.dep-sentinel`.
   Requires VS Code 1.90 or later. No account, API key or configuration needed.
2. **Open a project.** DepSentinel scans automatically (startup, every hour, and whenever a manifest or lockfile changes).
   To scan right away, click the **🛡 shield in the status bar** → *Scan now*.
3. **Look at the results.** They appear in three places:

   | Where | What you see |
   |---|---|
   | **DepSentinel view** (shield in the Activity Bar) | Files → affected packages → advisories, supply-chain signals and the dependency path. The badge shows how many packages are affected. |
   | **Above the dependency line** (CodeLens) | `🛡 2 vulnerabilities (critical) · fix → 1.2.6` or `☠ MALICIOUS package – remove it` |
   | **Problems panel** (`Ctrl+Shift+M`) | One entry per advisory with a link to GitHub Advisory / NVD / OSV |

4. **Fix.** Click the CodeLens, or press **`Ctrl+.`** on the line:
   - *Upgrade X to Y* (same major, safe) or *Upgrade X to Z ⚠ major version* (fixes everything)
   - *Force transitive X → Y* for vulnerable sub-dependencies (npm `overrides`, Maven `<dependencyManagement>`)
   - *Open advisory* / *Ignore advisory*
5. **Share.** Status bar → *Export report…* → Markdown for your team, or SARIF for code scanning. Use the CLI to fail CI builds.

The built-in **Getting Started** walkthrough (`DepSentinel: Getting Started`, or *Help → Welcome*) covers the same steps interactively.

### Everyday actions

| I want to… | Do this |
|---|---|
| Scan now | Status bar shield → *Scan now*, or the ⟳ button in the view |
| See only what matters | View title → **filter**: *Critical & high*, *Supply-chain risks*, *Direct only*, *Hide dev deps* |
| Stop background checks for a while | Status bar → *Pause monitoring* (manual scans still work) |
| Hide an advisory that doesn't apply | Right-click it → *Ignore This Advisory* (or `Ctrl+.` → *Ignore*) |
| Accept a "suspicious" package after review | Right-click the package → *Trust Package* |
| Use a company registry/mirror | Settings → `supplyChain.allowedRegistries`, `mavenRepositories`, `npmRegistry` |
| Turn off the inline summaries | Settings → `depSentinel.codeLens` |

## What it does

- **Re-checks every hour** (configurable) against the latest advisories, plus immediately whenever a manifest/lockfile changes.
- **Full dependency tree:** lockfiles are parsed into a real graph. For manifests without a lockfile (`package.json`, `pom.xml`,
  `build.gradle`), the transitive tree is resolved from npm / Maven Central. Maven resolution handles parent POMs, BOM imports,
  property interpolation, exclusions and nearest-wins.
- **Shows exactly where an issue comes from:** each finding shows the path (`spring-boot-starter-web › spring-web › spring-beans`) and is
  reported in the Problems panel on the line of the direct dependency that pulls it in.
- **Notifies only on *new* issues**, so you're alerted once and not nagged every hour.
- **Marks dependencies SUSPICIOUS** using supply-chain risk signals.

## Supported files

| Ecosystem | Files |
|---|---|
| npm / Node | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 + Berry), `pnpm-lock.yaml` (v5–v9), `package.json` (registry-resolved) |
| Java | `pom.xml` (transitive via Maven Central), `build.gradle(.kts)`, `gradle.lockfile`, `gradle/libs.versions.toml` |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` (pip-compile `# via` trees supported) |
| Go | `go.mod` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `packages.lock.json`, `*.csproj` |

## Data sources (free, no API key)

- **[OSV.dev](https://osv.dev):** aggregates GitHub Security Advisories, NVD CVEs, PyPA, Go, RustSec, and the
  **OpenSSF Malicious Packages** feed (`MAL-*` ids) that tracks known supply-chain attacks.
- **[deps.dev](https://deps.dev):** publish dates and release history.
- **npm registry:** publisher, maintainers, install scripts, provenance attestations.
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):** CVEs that attackers are actively
  exploiting. These are marked **🔥 Exploited** and fixed first.
- **[FIRST EPSS](https://www.first.org/epss/):** the estimated chance a CVE is exploited in the next 30 days. A score of
  10% or more raises a finding's priority by one step.

## Supply-chain risk signals

Each signal adds to a risk score. At or above `supplyChain.suspicionThreshold` (default 5), the package is marked **⚠ SUSPICIOUS**.

| Signal | Score | Why |
|---|---|---|
| `known-malicious` | 100 | Listed in OSV / OpenSSF malicious-packages, or a GHSA malware advisory |
| `install-script-added` | 5 | New `preinstall`/`postinstall` that the previous version didn't have (the classic hijack pattern) |
| `provenance-dropped` | 5 | Previous version was published from CI with provenance, this one wasn't (possible stolen token) |
| `untrusted-registry` | 5 | Lockfile resolves a package from a non-allow-listed host (dependency confusion / lockfile tampering) |
| `fresh-release` | 4 / 3 | Published < 24 h / < `recentPublishHours` ago, before advisories usually exist |
| `typosquat` | 4 | Name is one edit away from a popular package (`expres`, `crossenv`, `reqeusts`…) |
| `insecure-transport` | 4 | Resolved over plain HTTP |
| `publisher-changed` | 3 | Published by an account that wasn't a maintainer of the previous version (and without provenance) |
| `new-package` | 3 | Package first appeared < 30 days ago |
| `git-source` / `url-source` | 3 | Installed from git or an arbitrary tarball, bypassing the registry |
| `dormant-revival` | 2 | New release after more than a year of inactivity |
| `install-script` / `missing-integrity` / `deprecated` | 1 | Weak signals that add to others |

## Fixing issues

Each vulnerable package gets two recommendations:

- **Same-major fix:** the best release on your current major line, e.g. `Upgrade to 3.2.25 – same major, fixes 24 of 37`.
  This is the low-risk change.
- **Fixes-everything version:** used when some advisories are only fixed on a newer major (end-of-life lines such as
  Django 3.2 or Spring 5.3), e.g. `5.2.17 fixes all (major upgrade)`.

Only versions that were **publicly released** are recommended. Advisories sometimes list commercial-only backports
(e.g. Spring 5.3.42 is not on Maven Central), and recommending those would break your build.

On a flagged line, press **Ctrl+.** (💡) for:
- **Upgrade X to Y** (preferred, same major) and **Upgrade X to Z ⚠ major version**: edits the version in `package.json`
  (keeps `^`/`~`), `pom.xml` (edits the `${property}` if the version is one), `requirements.txt`, `build.gradle(.kts)` or `go.mod`.
- **Force transitive X → Y:** for vulnerable sub-dependencies, shown on the line of the dependency that pulls them in.
  - npm: adds `"overrides": { "qs@6.7.0": "6.7.3" }`. The version selector replaces only the vulnerable copy.
  - pnpm: uses `pnpm.overrides`. Yarn: uses `resolutions`, which applies to all copies.
  - Maven: adds a `<dependencyManagement>` pin. Maven applies the root's managed versions to transitive dependencies.
  - Only same-major versions are offered, because forcing a transitive dependency onto a new major usually breaks its parent.
- **Open advisory** / **Ignore advisory**.

If a lockfile is what gets scanned, it offers to run `npm/yarn/pnpm install` afterwards. That command only runs when you click the button.
Versions managed by a parent POM / BOM are not edited; use the transitive pin instead.

## Use it in CI

Want the same checks on every pull request? A command-line version with SARIF, Markdown and JSON output and
`--fail-on` exit codes is available from the GitHub repository. See [docs/cli.md](docs/cli.md).

## UI

- **Activity-bar view "DepSentinel"**: findings grouped by file → package → advisories and signals. Right-click to ignore an
  advisory or trust a package.
- **Problems panel** diagnostics with links to each advisory (GHSA / NVD / OSV).
- **Status bar** summary (`2C 5H 14 vulns · 1 ⚠`), red when something critical or malicious is present.
- **Report** (`DepSentinel: Show Security Report`): an HTML overview of everything found.

## Settings

| Setting | Default | |
|---|---|---|
| `depSentinel.scanIntervalMinutes` | `60` | Background re-check interval |
| `depSentinel.scanOnChange` | `true` | Re-scan when a manifest/lockfile changes |
| `depSentinel.minimumSeverity` | `low` | Hide vulnerabilities below this severity |
| `depSentinel.includeDevDependencies` | `true` | Include dev/test deps |
| `depSentinel.notifications` | `new` | `new` / `all` / `off` |
| `depSentinel.resolveTransitive` | `true` | Resolve sub-dependencies from registries when no lockfile exists |
| `depSentinel.mavenRepositories` | Maven Central | Add your Nexus/Artifactory URL for private POMs |
| `depSentinel.npmRegistry` | registry.npmjs.org | |
| `depSentinel.ignoredAdvisories` | `[]` | GHSA/CVE ids to suppress |
| `depSentinel.exploitData.enabled` | `true` | Use CISA KEV and EPSS to rank what's actually being exploited. Turn off for offline use |
| `depSentinel.supplyChain.*` | | Thresholds, allowed registries, trusted packages |

## Security & privacy

- **Only package names and versions** leave your machine (to OSV.dev, deps.dev and the package registries), plus the
  public CVE ids of found advisories (to api.first.org for EPSS scores). The CISA KEV catalog is downloaded whole. No
  source code, file paths, credentials or telemetry are sent.
- **Nothing from your projects is ever executed.** Manifests are read as text, and hostile files are handled safely
  (no prototype pollution, no XML entity expansion, size limits, workspace-only file access).
- **HTTPS only**, including redirects. Plain HTTP is allowed only for `localhost` mirrors.
- **Restricted Mode aware:** in untrusted workspaces, settings that could hide findings or redirect traffic are taken
  from your user settings only. Any suppression is always shown at the top of the DepSentinel view.

See [SECURITY.md](SECURITY.md) for the full threat model, the dependency policy and how to report a vulnerability.

## Limitations

- `go.mod` and `gradle.lockfile` have no edge information, so indirect modules are shown as transitive without a path.
- Unpinned `requirements.txt` entries can't be checked precisely. Use pip-compile / `pip freeze` output or a lockfile.
- Maven version ranges resolve to their lower bound. Profiles and `settings.xml` mirrors are not evaluated.
- Heuristic signals can produce false positives. Use *Trust Package* after reviewing a package.

## Contributing

Bug reports, false-positive reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
Please report security issues privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Afzaal Shoukat
