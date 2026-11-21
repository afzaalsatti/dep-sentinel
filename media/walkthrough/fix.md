# Fix with one click

Click the **CodeLens** above a flagged dependency, or put the cursor on the line and press **`Ctrl+.`**:

| Action | What it does |
|---|---|
| **Upgrade X to Y** ⭐ | Stays on your current major version, so it's the safe choice. Keeps `^`/`~` ranges. |
| **Upgrade X to Z ⚠ major version** | Fixes *everything*, but may contain breaking changes. |
| **Force transitive X → Y** | For vulnerable **sub-dependencies**: adds an npm `overrides` entry (only the vulnerable copy), `pnpm.overrides`, Yarn `resolutions`, or a Maven `<dependencyManagement>` pin. |
| **Open advisory** / **Ignore** | Read the details, or suppress an advisory that doesn't apply to you. |

Works in `package.json`, `pom.xml` (including `${property}` versions), `requirements.txt`, Gradle and `go.mod`.

**Only versions that were actually released are suggested.** Some advisories list commercial-only fixes; those are skipped.

After editing `package.json`, DepSentinel offers to run `npm install` so the lockfile picks up the change.
Nothing runs unless you click.

☠ **Malicious packages have no "upgrade".** Remove them and rotate any credentials on machines where they were installed.
