# We Pointed CyberHawk at a Real Windows Development Folder

**Test date:** July 22, 2026<br>
**Target:** a local Windows development portfolio under `C:\new`<br>
**Mode:** read-only OSV import, lockfile admission audit, persistent local dashboard

We did not build a hand-picked demo repository. We pointed CyberHawk at an active development folder and asked three separate questions:

1. Which known vulnerabilities appear in the dependency inventory?
2. What can the lockfiles actually prove about the package artifacts?
3. What should an autonomous remediation workflow be allowed to do next?

## The result

| Evidence | Measured result |
|---|---:|
| Scan inputs | 78 |
| Projects represented | 60 |
| Package occurrences inspected by the vulnerability scan | 27,474 |
| Unique package coordinates | 8,248 |
| Project/package/advisory finding occurrences | 2,530 |
| Projects with at least one finding | 55 |
| Critical / high / moderate / low / unknown | 58 / 949 / 976 / 215 / 332 |
| Findings with an identified fixed version | 1,943 |
| Direct dependencies with an identified fix | 463 |

An early optional experiment intersected the result with that week's 19-item PickBits editorial brief and returned zero direct CVE-ID matches. That sentence has an important boundary: it means no IDs intersected, not that the folder was secure and not that every editorial item could be mapped perfectly to an ecosystem package and version. The current CyberHawk workflow uses OSV by default and does not require this editorial overlay.

## What the trust gate found

The admission audit independently inspected 28,182 npm lockfile entries across 72 `package-lock.json` files. Its counts differ from the vulnerability inventory because it evaluates lockfile records rather than OSV's normalized result groups.

| Admission state | Count | Share |
|---|---:|---:|
| `ALLOW_LOCKED` | 25,816 | 91.6% |
| `REVIEW` | 2,123 | 7.5% |
| `QUARANTINE` | 243 | 0.9% |
| `BLOCK` | 0 | 0.0% |

`ALLOW_LOCKED` is intentionally narrow. It means the exact package version had an integrity value and resolved through the approved npm registry. It does **not** mean CyberHawk verified the publisher or certified the package as safe.

Every one of the 28,182 assessments retained `publisher provenance: unknown`. Of the exceptions, 1,657 lacked integrity evidence, 466 were linked to critical or high findings, and 243 declared install lifecycle scripts and were quarantined from automated execution.

## We verified the scanner, too

The local OSV-Scanner 2.4.0 Windows binary produced this SHA-256 digest:

```text
0cdd113610126d5dfd5e12ad0e0b4f3e879291ff19bb43b0c52ed2f2c2df1a37
```

It exactly matched the digest in the official GitHub release metadata for `osv-scanner_windows_amd64.exe`. The release exposed provenance material, but this prototype did not cryptographically verify the SLSA statement, and the binary did not have a verified Authenticode signature. The dashboard therefore says `DIGEST_VERIFIED`, not “trusted.”

## We tripped our own trap

We generated a localhost-only defensive canary, then deliberately touched its unique callback as a controlled test. The caller received a generic `404`; the dashboard persisted one critical canary event. No exploit, secret, or third-party system was involved.

The prompt-injection heuristic also did something useful during tuning: a broad phrase matched benign vulnerability prose. We inspected it, removed the ambiguous phrase from policy, reran the audit, and got zero signals. That is why a heuristic match is review evidence, not a guilty verdict.

## What you can do from the report

The portfolio report exposes filterable findings and copyable remediation requests. Those requests are typed JSON containing only a constrained operation, package, installed version, fixed version, advisory, manifest, and approval state. Free-form advisory prose is not converted into a command.

Today the workflow is deliberately report-only. It does not silently install packages or claim that a queued item has been fixed. The safe next increment is a sandboxed executor with a policy gate, lifecycle scripts disabled, tests and a rescan, a reviewable diff, and closure only after repeated complete scans.

## The product idea

CyberHawk is not “Dependabot on your laptop.” It is an open-source, local vulnerability-response layer for code that may live across many repositories or never reach GitHub. It preserves scan history, separates artifact evidence from publisher trust, makes remediation authority explicit, and gives defensive AI canaries a place in the same operational record.

The honest promise is smaller—and more useful—than “secure your software”:

> Point CyberHawk at a code folder. It will show what is vulnerable, what is verifiable, what needs human judgment, and whether an automated system crossed a boundary you told it not to cross.

All figures above are point-in-time observations from one local test. They will change as repositories, advisories, and dependency graphs change. Project names and source paths are intentionally omitted from the public result.
