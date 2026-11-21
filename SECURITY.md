# Security Policy

DepSentinel is a security tool, so it must not become an attack vector itself. This document describes
how to report a vulnerability, what DepSentinel defends against, and the rules its own supply chain follows.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (*Security → Report a vulnerability*). Do not open a public issue.

Please include the version, a description, and steps or a sample manifest/lockfile that reproduce the problem.
We aim to acknowledge reports within 3 working days and to ship a fix for confirmed high/critical issues within 14 days.

| Version | Supported |
|---|---|
| 1.x | ✅ |
| < 1.0 | ❌ (pre-release) |

## Threat model

DepSentinel reads files from repositories you open (which may be hostile) and data from public services
(which could be compromised or impersonated). It treats **both as untrusted**.

| Threat | Mitigation |
|---|---|
| **Code execution from a scanned repository** | DepSentinel never installs, builds or runs anything from a project. Manifests are parsed as text. The optional "refresh lockfile" button after a Quick Fix runs only lockfile-only commands with `--ignore-scripts` (`npm install --package-lock-only --ignore-scripts`), only after an explicit click, and never in an untrusted workspace. |
| **Prototype pollution via crafted TOML/JSON/YAML/XML** (`[__proto__.x]`) | TOML tables use null-prototype objects and `__proto__` / `constructor` / `prototype` keys are rejected. Maven property lookups are own-property only. Covered by `src/test/security.test.ts`. |
| **XML entity attacks** (billion laughs, XXE) in POMs | Entity processing is disabled. External entities make the file fail to parse instead of being resolved. |
| **YAML alias bombs** in lockfiles | Alias expansion is capped (`maxAliasCount`). |
| **Resource exhaustion** | Manifests over 32 MB and non-regular files are skipped. HTTP responses are capped at 64 MB (declared and streamed), with timeouts. Dependency-tree resolution is depth- and size-bounded. |
| **Path traversal** (`<relativePath>../../../etc</relativePath>`) | Local files are only read inside the open workspace folders (or the CLI's scan root). The CLI never follows symlinks. |
| **A repository silencing its own findings** via committed `.vscode/settings.json` (`ignoredAdvisories`, `trustedPackages`, custom registry…) | In untrusted workspaces these settings are ignored (`restrictedConfigurations`). In all workspaces every suppression is listed at the top of the DepSentinel view, flagged ⚠ when it comes from the workspace itself. |
| **Tampered or redirected network traffic** | HTTPS only: plain HTTP is refused (except `localhost` mirrors), including in redirects. Each redirect hop is validated *before* it is requested, and at most 5 hops are followed. No credentials or cookies are sent. Registry URLs from settings are validated. |
| **Malicious content in advisory data** (links, markup) | Only `http(s)` advisory links are opened or rendered (`command:`, `file:`, `vscode:` and `javascript:` are dropped). Tooltips escape all external text. The report webview runs with scripts, forms, command links and local resources disabled under a strict CSP. Markdown/SARIF exports escape HTML. |

## Data handling and privacy

- **Sent:** package **names and versions**, to OSV.dev, deps.dev, the npm registry, Maven Central/your configured
  repositories, RubyGems and Packagist.
- **Never sent:** source code, file contents, file paths, user names, tokens, or telemetry. DepSentinel has no telemetry.
- **Cached** under VS Code's extension storage (CLI: `~/.cache/dep-sentinel`, override with `DEP_SENTINEL_CACHE`).
  Use *DepSentinel: Clear Cache* to remove it.

## DepSentinel's own supply chain

| Rule | How |
|---|---|
| Few runtime dependencies | 4: `fast-xml-parser`, `jsonc-parser`, `semver`, `yaml`. Everything is bundled into `dist/`; the VSIX ships no `node_modules`. |
| Exact versions + lockfile | `save-exact=true`; all versions pinned in `package.json`; installs use `npm ci`. |
| No install scripts | `.npmrc` → `ignore-scripts=true` for every install, locally and in CI. |
| Minimum release age of 7 days | New dependency versions are only adopted once they are at least a week old (`npm install --before=<date>`, Dependabot `cooldown: 7`). |
| Known-vulnerability gate | `npm audit` must report 0 vulnerabilities (`npm run audit:deps`). Transitive fixes are forced via `overrides` when needed. |
| Dogfooding | CI scans DepSentinel's own lockfile with DepSentinel (`npm run scan:self`, fails on medium+) and publishes the SARIF to code scanning. |
| Pinned CI | GitHub Actions are pinned to full commit SHAs, workflows default to `contents: read`, and checkouts don't persist credentials. |
| Verifiable artifacts | `npm run package` writes `dep-sentinel-<version>.vsix.sha256`. Verify with `sha256sum -c` or `Get-FileHash`. |
| Minimal package | `.vscodeignore` is an allow-list: only `dist/extension.js`, `media/`, `package.json`, `README.md` and `CHANGELOG.md` are shipped. |

### Reviewed findings in our own dependency tree

| Package | Finding | Review |
|---|---|---|
| `jszip@3.10.2` (dev, via `@vscode/test-electron`) | LOW: published by `jkoops` instead of `stuk` | `jkoops` is a listed long-time JSZip co-maintainer. Only used by the test runner to unpack VS Code builds. |
| `@isaacs/nonrecursive-glob-match@1.1.0` (dev, via `minimatch`) | LOW: package younger than 30 days | Published by `isaacs`, the author of `minimatch`. |

`test-fixtures/` intentionally contains manifests that reference known-malicious packages. They are text only
and are excluded from the self-scan. **Never run a package manager in that folder.**
