# Contributing to DepSentinel

Thanks for helping! Bug reports, false-positive reports and pull requests are welcome.
For security issues, **do not open a public issue**. Follow [SECURITY.md](SECURITY.md) instead.

## Setup

Requires **Node.js 22** (see `.nvmrc`) to build and test. The packaged extension runs inside VS Code 1.90+, and the
CLI runs on Node.js 18.18 or later.

```bash
npm ci                     # exact lockfile install; .npmrc blocks dependency install scripts
npm test                   # typecheck + bundle + unit tests (incl. security regression tests)
npm run test:integration   # downloads VS Code and runs the extension end to end
npm run verify             # tests + npm audit + DepSentinel scanning its own dependencies
npm run package            # dep-sentinel-<version>.vsix + .sha256 checksum
```

Press **F5** in VS Code ("Run DepSentinel") to launch an Extension Development Host with your changes.

## Project layout

| Path | Contents |
|---|---|
| `src/core/` | The engine, with **no VS Code dependency**: manifest/lockfile parsers, npm & Maven resolvers, OSV client, supply-chain heuristics, fix recommendations, exporters, scanner |
| `src/*.ts` | VS Code integration: scheduler, tree view, diagnostics, CodeLens, quick fixes, report webview |
| `src/cli.ts` | Command-line interface (see [docs/cli.md](docs/cli.md)) |
| `src/test/` | Unit and security regression tests (`node --test`) |
| `src/test-integration/` | End-to-end tests inside a real VS Code instance |
| `test-fixtures/` | ⚠ Manifests that **intentionally** reference vulnerable and malicious packages. Text only: never run a package manager there |
| `media/` | Icons and the Getting Started walkthrough pages |
| `scripts/` | Icon generator and release checksum script |

## Pull requests

- `main` is protected: changes go through a pull request, and CI (tests on Ubuntu and Windows, packaging) must pass.
- Add or update tests for behaviour changes. Parsers and heuristics should get a unit test with a minimal fixture.
- Keep `npm run verify` green: no `npm audit` findings and no medium+ findings in the self-scan.

## Dependency policy

DepSentinel is a security tool, so its own supply chain is held to a strict standard (details in [SECURITY.md](SECURITY.md)):

- Keep runtime dependencies to a minimum; everything is bundled into `dist/`.
- Pin exact versions (`save-exact=true`) and only adopt releases **older than 7 days**.
- Never enable dependency install scripts (`.npmrc` → `ignore-scripts=true`).
- `@types/vscode` must match the minimum VS Code version in `engines.vscode`.

## Releasing

1. Bump `version` in `package.json` (`npm version <x.y.z> --no-git-tag-version`), update `TOOL_VERSION` in
   `src/core/exporters.ts`, and add a `CHANGELOG.md` entry.
2. Merge the pull request. CI on `main` builds `dep-sentinel-<version>.vsix` and its `.sha256` as the `dep-sentinel-vsix` artifact.
3. Verify the checksum, then upload the VSIX on the [Marketplace management page](https://marketplace.visualstudio.com/manage)
   (publisher **afzaalshoukat** → DepSentinel → *Update*).
4. Tag the release (`git tag v<version> && git push origin v<version>`) and attach the VSIX and checksum to a GitHub Release.
