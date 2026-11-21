# ⚠ Test fixtures – do NOT install

`workspace/` contains manifests and lockfiles that deliberately reference **known-vulnerable and known-malicious
packages** (event-stream 3.3.6 / flatmap-stream 0.1.1, log4j-core 2.14.1, minimist from a fake mirror, …).

They exist only as **text** for DepSentinel's integration tests. The extension reads them; it never downloads or runs them.

- Do **not** run `npm install`, `mvn`, `gradle`, or `pip install` in these folders.
- The integration test copies `workspace/` to a temp directory and deletes it afterwards.
- `workspace/.npmrc` sets `ignore-scripts=true`, and the lockfile integrity hashes are fake, as extra guards.
