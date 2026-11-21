# Tune monitoring

Click the **🛡 shield in the status bar** for every action: scan, report, export, filter, pause/resume, settings.

Useful settings:

| Setting | Default | |
|---|---|---|
| `scanIntervalMinutes` | `60` | How often to re-check against new advisories |
| `minimumSeverity` | `low` | Hide vulnerabilities below this level |
| `includeDevDependencies` | `true` | Include dev/test dependencies |
| `notifications` | `new` | `new` · `all` · `off` |
| `codeLens` | `true` | Summary above affected dependency lines |
| `mavenRepositories` | Maven Central | Add your Nexus/Artifactory for private POMs |
| `supplyChain.allowedRegistries` | public registries | Add your company mirror |
| `supplyChain.trustedPackages` | `[]` | Packages you have reviewed |
| `ignoredAdvisories` | `[]` | Advisory IDs that don't apply to you |

**Pause monitoring** (status bar → *Pause*) stops hourly and on-change scans in this workspace. Manual scans still work.
