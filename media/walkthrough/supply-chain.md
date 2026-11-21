# Understand supply-chain warnings

CVEs only cover *known* bugs. Supply-chain attacks (hijacked maintainer accounts, typosquats, backdoored releases)
are usually live for hours or days before an advisory exists. DepSentinel looks for the warning signs:

| Signal | Example |
|---|---|
| ☠ **known-malicious** | Listed in the OpenSSF Malicious Packages feed (`MAL-…`) |
| **install-script-added** | New `postinstall` script that the previous version didn't have |
| **provenance-dropped** | Previous release was built by CI with provenance; this one was published by hand |
| **fresh-release** | Published less than 24–72 h ago |
| **publisher-changed** | Published by an account that wasn't a maintainer before |
| **typosquat** | `expres`, `crossenv`, `reqeusts`… |
| **untrusted-registry** | Lockfile downloads the package from an unknown host |

Each signal adds to a **risk score**. Past the threshold (default 5), the package is marked **⚠ SUSPICIOUS**.

**What to do:** check the package's changelog and repository. If it's fine, right-click → **Trust Package**.
If not, pin the previous version.

Company mirror flagged as untrusted? Add it to `depSentinel.supplyChain.allowedRegistries`.
