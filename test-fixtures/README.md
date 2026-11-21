# ⚠ Test fixtures – do NOT install

`workspace/` contains manifests and lockfiles that deliberately reference **known-vulnerable and known-malicious
packages** (event-stream 3.3.6 / flatmap-stream 0.1.1, log4j-core 2.14.1, minimist from a fake mirror, …).

They exist only as **text** for DepSentinel's integration tests. The extension reads them; it never downloads or runs them.

- Do **not** run `npm install`, `mvn`, `gradle`, or `pip install` in these folders.
- The manifests are stored as `*.fixture` (e.g. `package-lock.json.fixture`) so GitHub's dependency graph, Dependabot and
  other scanners don't treat them as real dependencies of this repository.
- The integration test copies `workspace/` to a temp directory, restores the real file names there, and deletes it afterwards.
- `workspace/.npmrc` sets `ignore-scripts=true`, and the lockfile integrity hashes are fake, as extra guards.
