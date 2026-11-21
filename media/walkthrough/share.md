# Share & protect pull requests

### Export a report

**DepSentinel: Export Report…** (or the `…` menu in the view title):

- **Markdown**: summary table plus per-file findings with recommended fixes. Paste it into a PR, ticket or chat.
- **SARIF 2.1.0**: for GitHub code scanning, Azure DevOps and other security dashboards.
- **JSON**: the raw results.

### Run the same scanner in CI

The extension ships with a CLI that uses the same engine:

```bash
node dist/cli.js . --fail-on high --sarif depsentinel.sarif --markdown report.md
```

Exit code `1` when something at or above `--fail-on` is found, so the build fails before a vulnerable or
malicious dependency is merged.

```yaml
# GitHub Actions
- run: node tools/dep-sentinel/dist/cli.js . --fail-on high --sarif depsentinel.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: depsentinel.sarif }
```
