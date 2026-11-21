# Run your first scan

DepSentinel scans **automatically**: on startup, **every hour**, and whenever a manifest or lockfile changes.
You can also start a scan yourself at any time:

- Click **Scan Now** on the left, or
- click the **🛡 shield** in the status bar → *Scan now*, or
- run **DepSentinel: Scan Dependencies Now** from the Command Palette (`Ctrl+Shift+P`).

### What gets scanned

| Ecosystem | Files |
|---|---|
| npm / Node | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` |
| Java | `pom.xml`, `build.gradle(.kts)`, `gradle.lockfile`, `libs.versions.toml` |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` |
| Go · Rust · Ruby · PHP · .NET | `go.mod`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `packages.lock.json` |

**Sub-dependencies are included.** Lockfiles are read as a full dependency tree. Without a lockfile, the tree is
resolved from npm or Maven Central.

> 🔒 Only package **names and versions** are sent to OSV.dev / deps.dev. Your code never leaves your machine,
> and nothing is ever installed or executed.
