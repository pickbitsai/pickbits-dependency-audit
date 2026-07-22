# PickBits Dependency Audit — Product Direction

## Recommendation

Ship an open-source, cross-platform command-line watchdog first, then wrap the same engine with a thin Windows quick-launch experience. The engine must behave consistently from a terminal, cron, Windows Task Scheduler, CI, or an approved agent routine.

PickBits Dependency Audit uses OSV as its default vulnerability source. It does not require a PickBits feed. A team may supply its own local CVE watchlist as an optional priority overlay.

## Product promise

> Audit a code folder. See what is vulnerable, what the package evidence can prove, what needs human judgment, and whether a proposed fix stayed fixed.

This is a dependency vulnerability watchdog, not antivirus. It does not inspect arbitrary executables, memory, malware behavior, or source-code reachability.

## Working prototype

The current source prototype includes:

- OSV JSON ingestion and a standalone local HTML report;
- portfolio-wide filtering and aggregate results;
- a persistent SQLite evidence store;
- two-complete-scan verification before closure;
- npm lockfile admission states;
- typed remediation requests with human approval;
- scanner-release digest verification;
- harmless localhost defensive canaries;
- a public-safe dashboard mode; and
- a reproducible 30-second demo video.

The scheduled standalone binary, sandboxed patch executor, Windows installer, and managed fleet collector have not shipped.

## Architecture

```text
Local manifests and lockfiles
             |
             v
        OSV-Scanner -------- optional local CVE watchlist
             |                         |
             +-----------+-------------+
                         v
                normalized findings
                         |
          +--------------+---------------+
          v              v               v
   trust policy    persistent state   typed actions
          |              |               |
          +--------------+---------------+
                         v
              local HTML + dashboard
```

The watchlist is local, explicit, and user-controlled. The engine never needs to scrape editorial prose or call PickBits to complete a scan.

## Stable command surface

The current prototype deliberately exposes the tested OSV and Node.js commands. A future standalone CLI may converge on:

```text
pickbits-audit scan <folder>
pickbits-audit report <scan-id>
pickbits-audit watchlist scan <folder> --file <local-file>
pickbits-audit schedule add <folder> --weekly
pickbits-audit schedule list
pickbits-audit doctor
```

`scan` must never install dependencies or invoke lifecycle scripts. It should write reports outside the source tree by default and disclose every network destination used for advisory metadata.

## Trust policy

Package trust is a set of independent gates, not a green badge:

| State | Evidence | Meaning |
|---|---|---|
| `ALLOW_LOCKED` | exact version, integrity, approved registry | the exact artifact may be analyzed |
| `REVIEW` | incomplete evidence or high-priority vulnerability | a person must decide |
| `QUARANTINE` | active package content such as lifecycle scripts | do not execute automatically |
| `BLOCK` | hard policy failure | stop the workflow |

Publisher provenance remains unknown until a separate attestation or signature gate verifies it. Digest equality proves byte identity, not safety.

## Safe remediation executor

The future executor should accept only the typed remediation schema and apply configured low-risk changes when every gate passes:

1. clean Git working tree;
2. exact package and fixed version still match the current finding;
3. patch- or minor-version change only;
4. no lifecycle scripts, source override, or registry change;
5. lockfile regeneration with scripts disabled;
6. existing tests pass in isolation;
7. rescan removes the finding;
8. diff is retained for human review; and
9. closure occurs only after repeated complete scans.

Major upgrades, packages without fixed versions, incomplete provenance, test failures, and canary events must suspend automatic writes.

## Report states

| State | Meaning |
|---|---|
| Open | observed in the latest complete scan |
| Pending verification | absent from one complete scan |
| Closed — fixed | absent from the configured number of complete scans |
| Unresolved | evidence could not be mapped or verified |

An incomplete scan never advances closure and never yields an unqualified clean result.

## Windows package

Build a signed per-user installer after the CLI and report schema stabilize. The first Windows release should provide:

- Start Menu shortcut;
- Explorer “Audit dependencies with PickBits” action;
- folder picker and saved targets;
- Scan Now button;
- report history and last-run status;
- weekly Task Scheduler toggle; and
- notifications only for new or worsened findings.

Do not begin with a permanent endpoint agent. Scheduled and on-demand execution is easier to audit and earns trust incrementally.

## SMB product model

Keep the engine, schemas, renderer, policies, and scheduler adapters open source. A commercial team layer can add:

- endpoint inventory and policy distribution;
- aggregate evidence without source upload;
- role-based approvals;
- exception and SLA workflows;
- ServiceNow/Jira/GitHub integrations;
- signed policy bundles;
- fleet reporting; and
- support for release provenance and private registries.

The durable advantage is operational workflow and trustworthy normalization—not hiding the scanner.

## Differentiation

PickBits Dependency Audit complements repository-native tools:

- Dependabot is strong at GitHub-native update pull requests.
- OSV-Scanner is the source of truth for package/advisory matching.
- PickBits Dependency Audit adds local portfolio discovery, persistent remediation state, artifact-admission evidence, constrained agent actions, and defensive canaries.

## Release gates

Do not call the unattended watchdog generally available until:

- clean-machine installation reaches a report in under two minutes;
- Windows, macOS, and Linux smoke tests pass;
- hostile package strings pass escaping and prompt-boundary tests;
- incomplete data never produces a green result;
- release checksums, signatures, and SBOMs publish successfully;
- patch execution is isolated and reviewable; and
- privacy documentation matches observed network behavior.
