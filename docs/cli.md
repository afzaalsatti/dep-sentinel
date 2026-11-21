# DepSentinel CLI

The same engine as the VS Code extension, as a command-line tool for CI pipelines and pre-commit checks.
It is not part of the Marketplace extension; build it from this repository.

## Build

Requires Node.js 22 to build. The resulting `dist/cli.js` runs on Node.js 18.18 or later and has no runtime dependencies.

```bash
git clone https://github.com/afzaalsatti/dep-sentinel.git
cd dep-sentinel
npm ci            # .npmrc in this repository blocks dependency install scripts
npm run compile   # produces dist/cli.js
```

## Usage

```bash
node dist/cli.js [path] --fail-on high --sarif depsentinel.sarif --markdown report.md
```

| Option | |
|---|---|
| `--fail-on <low\|medium\|high\|critical\|none>` | Exit code 1 if anything is at/above this level (default `high`). Suspicious = high, malicious = critical |
| `--sarif <file>` | SARIF 2.1.0 report with results located on the manifest line (GitHub code scanning, Azure DevOps) |
| `--json <file\|->` | Full results as JSON (`-` for stdout) |
| `--markdown <file>` | Markdown report for PR comments, tickets or chat |
| `--exclude <dirs>` | Comma-separated directories to skip, relative to the scan path |
| `--trust <name@version,…>` | Reviewed packages: suppresses their supply-chain signals (CVEs are still reported) |
| `--ignore <ids>` | Advisory IDs to ignore (`GHSA-…`, `CVE-…`) |
| `--min-severity <level>` | Hide vulnerabilities below this level |
| `--no-dev` | Skip dev/test dependencies |
| `--no-supply-chain` | Disable supply-chain heuristics |
| `-q`, `--quiet` | Only print the summary |

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` scan error.

The cache lives in `~/.cache/dep-sentinel`; override it with `DEP_SENTINEL_CACHE`.

## GitHub Actions

```yaml
permissions:
  contents: read
  actions: read            # required by upload-sarif
  security-events: write   # code scanning: public repos, or private with GitHub Advanced Security
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
    with: { persist-credentials: false }
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
    with: { repository: afzaalsatti/dep-sentinel, path: .dep-sentinel, persist-credentials: false }
  - run: npm ci && npm run compile
    working-directory: .dep-sentinel
  - run: node .dep-sentinel/dist/cli.js . --exclude .dep-sentinel --fail-on high --sarif depsentinel.sarif
  - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
    if: always()
    with: { sarif_file: depsentinel.sarif }
```

Pin actions to full commit SHAs, as above, rather than tags. For extra safety, pin the DepSentinel checkout to a
release tag or commit with `ref:`.
