# Share & protect pull requests

### Export a report

**DepSentinel: Export Report…** (or the `…` menu in the view title):

- **Markdown**: summary table plus per-file findings with recommended fixes. Paste it into a PR, ticket or chat.
- **SARIF 2.1.0**: for GitHub code scanning, Azure DevOps and other security dashboards.
- **JSON**: the raw results.

### Protect pull requests

A command-line version of the same engine can run in your CI pipeline. It fails the build (`--fail-on high`) before a
vulnerable or malicious dependency is merged, and can publish SARIF to GitHub code scanning.

Setup instructions and a GitHub Actions example are in the repository: [docs/cli.md](https://github.com/afzaalsatti/dep-sentinel/blob/main/docs/cli.md).
