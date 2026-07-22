# PickBits Dependency Audit — Zero-Trust Design

PickBits Dependency Audit treats a package name, lockfile, advisory, feed, report, and AI-generated recommendation as evidence, never as authority. An exact hash match can admit a specific artifact under a policy; it cannot prove that the publisher is honest or that the code is safe.

## Decision model

| State | Meaning | Automated action |
|---|---|---|
| `ALLOW_LOCKED` | Exact version, integrity value, and approved registry are present | May be analyzed; no install permission is implied |
| `REVIEW` | Evidence is incomplete or the package is linked to a high-priority finding | Human review required |
| `QUARANTINE` | Lifecycle scripts or another active-content risk is present | Isolate; do not execute |
| `BLOCK` | The source violates policy or the content crosses a hard safety boundary | Stop |

The current npm gate verifies what the lockfile can prove: a pinned coordinate, an integrity digest, an approved registry host, lifecycle-script metadata, and known-vulnerability context. It deliberately records publisher provenance as unknown. Registry attestations, Sigstore/SLSA verification, maintainer identity, and behavioral analysis belong to later independent gates.

## Untrusted-input boundary

Remote and package-controlled strings never become shell commands or agent instructions. PickBits Dependency Audit applies four rules:

1. Parse data into a narrow schema.
2. Validate package names, versions, advisory IDs, and operation types against allowlists.
3. Keep the proposed action as typed JSON until a separate executor is approved.
4. Render remote content with text-only DOM APIs and a restrictive Content Security Policy.

The report currently emits typed remediation requests with `approval: required`. It does not contain an automatic patch executor. A future executor should accept only this schema, re-read the current lockfile, refuse a dirty worktree by policy, install with lifecycle scripts disabled, run tests in isolation, rescan, and require two complete clean observations before closing an item.

## Persistent vulnerability response

The SQLite state store separates detection from closure:

```text
observed -> open
absent in one complete scan -> pending_verification
absent in two complete scans -> closed_fixed
```

An incomplete scan never advances closure. Scan runs, observations, trust assessments, release-tool verification, audit events, canaries, and canary hits are retained locally.

## Defensive canaries

PickBits Dependency Audit can create a harmless decoy document containing a unique marker and a localhost callback. Legitimate automation is told to stop and request human review. If the callback is touched, the dashboard records a critical event and returns a generic `404`.

This is a defensive tripwire, not a weapon:

- use it only in systems and data you control;
- do not include secrets or executable payloads;
- do not target third-party agents or services;
- treat a hit as a reason to investigate, not proof of malicious intent; and
- rotate or retire canaries that are disclosed publicly.

Prompt-injection matching remains heuristic. Signals are quarantined for review, and a match is never presented as proof that content is malicious.

## Local commands

Node.js 22.5 or newer is required for the prototype SQLite store.

```powershell
# Import an existing OSV JSON result, evaluate npm lockfiles, and persist the run.
node scripts/trust-audit.mjs --scan reports/osv-result.json --target C:\projects --db reports/dependency-audit-state.db --output reports/dependency-audit-run.json

# Serve the stateful dashboard locally.
node scripts/dashboard-server.mjs --db reports/dependency-audit-state.db --port 8787

# Create a localhost-only defensive canary.
node scripts/create-canary.mjs --db reports/dependency-audit-state.db --output reports/dependency-audit-local-canary.json --name local-demo --base-url http://127.0.0.1:8787
```

Release-tool verification is a separate command because a correct dependency result is not useful if the scanner binary itself is unverified:

```powershell
node scripts/verify-release.mjs --file C:\path\to\osv-scanner.exe --repository google/osv-scanner --tag v2.4.0 --asset osv-scanner_windows_amd64.exe --db reports/dependency-audit-state.db
```

Digest equality proves that the local bytes match the named release asset. It does not substitute for a verified provenance statement or a platform signature.
