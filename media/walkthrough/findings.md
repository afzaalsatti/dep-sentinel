# See what was found

Every issue is shown in three places:

**1. The DepSentinel view** (shield icon in the Activity Bar)

```
🛡 Last scan 10:42 · 1,204 pkgs · 9 vulns · 1 suspicious
└─ web/package-lock.json        npm · 412 pkgs · 3 vulns
   ├─ ⛔ minimist@1.2.0          direct · 2 vulns · fix → 1.2.6
   └─ ☠ flatmap-stream@0.1.1    via event-stream@3.3.6 · ⚠ SUSPICIOUS
      ├─ MAL-2025-20690  CRITICAL  Malicious code in flatmap-stream
      └─ Path: event-stream@3.3.6 › flatmap-stream@0.1.1
```

- Click a **package** to jump to the line that declares it.
- Click an **advisory** to open it (GitHub Advisory / NVD / OSV).
- Use the **filter** button to show only *critical & high*, *supply-chain risks*, *direct* or *production* dependencies.

**2. The Problems panel** (`Ctrl+Shift+M`). Each finding is attached to the line of the dependency you declared.
For sub-dependencies, that is the direct dependency that pulls them in.

**3. CodeLens above the dependency line:**

```json
  🛡 2 vulnerabilities (critical) · fix → 1.2.6
  "minimist": "1.2.0",
```

You get a notification only when **new** issues appear, so you're not nagged every hour.
