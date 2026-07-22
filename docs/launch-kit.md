# PickBits Dependency Audit — Launch Kit

## Positioning

**Category:** Local dependency vulnerability response for developers and small teams.

**Primary tagline:**

> Know what is vulnerable. Verify what can act.

**Campaign line:**

> Trust nothing in the dependency chain. Especially the instructions.

**One-sentence pitch:**

PickBits Dependency Audit is an open-source local workflow that scans dependency files with OSV, evaluates artifact evidence under a zero-trust policy, persists remediation state, and proposes constrained fixes for human approval.

**The honest differentiator:**

PickBits Dependency Audit is not another vulnerability database and does not depend on a PickBits feed. It is the operational layer between structured OSV findings and a safe, persistent remediation workflow for local code.

## Website hero

**Eyebrow:** OPEN SOURCE · LOCAL FIRST · HUMAN APPROVED

**Headline:** Trust nothing in the dependency chain. Especially the instructions.

**Subhead:** Audit one project or a folder full of them. Find vulnerable dependency versions, show what the lockfile can prove, quarantine active package content, and produce a local dashboard with reviewable actions.

**Primary CTA:** View the open-source project<br>
**Secondary CTA:** Watch the 30-second demo

**Trust line:** MIT licensed · report-only by default · no PickBits feed required · no source-code upload

## Short announcement

We built PickBits Dependency Audit for code that does not live in one perfect repository.

It is an open-source dependency vulnerability watchdog that scans local projects with OSV, persists findings across runs, evaluates npm lockfile evidence, and turns remediation into a typed request instead of a free-form command.

The zero-trust boundary is the product:

- exact locked artifacts can be admitted for analysis without claiming their publishers are trusted;
- lifecycle-script packages are quarantined from automation;
- advisory prose never becomes shell authority;
- findings close only after repeated complete scans; and
- harmless canaries record unexpected autonomous handling.

PickBits Dependency Audit is report-only today. The engine, policy, dashboard, tests, and demo are open source under MIT.

[Watch the demo] [View GitHub]

## LinkedIn post

Most dependency tools start with a repository.

We started with a folder.

PickBits Dependency Audit is an open-source vulnerability-response workflow for local code, prototypes, uncommitted work, and multi-repository portfolios. It uses OSV to identify known vulnerable package versions, then asks a separate question: what does the package evidence actually prove, and what should automation be allowed to do next?

In our measured Windows portfolio run:

- 27,474 package occurrences were inspected;
- 2,530 project/package/advisory findings were persisted;
- 25,816 exact locked artifacts met the admission policy;
- 2,123 package records required review; and
- 243 lifecycle-script packages were quarantined from automation.

Publisher provenance remained unknown. That is intentional. A checksum is evidence; it is not trust.

The workflow creates typed remediation requests, requires repeated complete scans before closure, verifies the scanner bytes, and supports harmless defensive canaries. It does not silently patch packages or pretend a missing join means secure.

PickBits Dependency Audit is open source under MIT. It uses OSV directly and does not depend on a PickBits feed.

[Watch the 30-second demo] [Inspect the source]

## Short social post

Your scanner found a CVE. PickBits Dependency Audit asks what happens next.

- local folder and portfolio scans
- structured OSV findings
- persistent remediation state
- exact-artifact admission evidence
- lifecycle-script quarantine
- typed, human-approved fixes
- defensive automation canaries

Open source. Report-only. No PickBits feed required.

[GitHub] [Demo]

## Hacker News / technical community post

**Title:** Show HN: PickBits Dependency Audit — local vulnerability response with zero-trust package gates

**Body:**

PickBits Dependency Audit is an open-source workflow around OSV-Scanner for code that may span many local folders or never reach GitHub. It imports structured vulnerability results, persists observations in SQLite, evaluates npm lockfile evidence, and produces a local HTML dashboard with typed remediation requests.

The package gate is deliberately narrow. Exact version + integrity + approved registry yields `ALLOW_LOCKED`, which permits analysis but does not establish publisher trust or install authority. Lifecycle scripts are quarantined. A finding closes only after repeated complete scans prove it absent.

The repo also contains a release-digest verifier, harmless localhost canaries for unexpected autonomous handling, policy tests, and a reproducible captioned demo.

The workflow is report-only today. Feedback on the evidence schema, sandboxed executor gates, and cross-platform packaging would be useful.

## 30-second video copy

The captioned video and production notes live in [demo-video.md](demo-video.md). The scene sequence is:

1. run PickBits Dependency Audit against a folder;
2. discover dependency inputs;
3. match versions to OSV;
4. evaluate trust evidence;
5. create a typed action;
6. verify repeated absence; and
7. review the local dashboard.

## Language boundary

| Use | Avoid |
|---|---|
| dependency vulnerability watchdog | virus scanner / antivirus |
| exact locked artifact admitted | package is safe / trusted |
| no source-code upload | nothing leaves the machine |
| known finding | exploitable vulnerability |
| controlled defensive canary test | attack detected |
| report-only prototype | autonomous patching |
| OSV is the default source | proprietary PickBits intelligence required |

## Launch checklist

- Keep CyberHawk references limited to the PickBits editorial vulnerability feed; the software name is PickBits Dependency Audit.
- Rename the GitHub repository slug if the final product name is approved.
- Publish the rendered WebM and poster with the `/cyberhawk/audit/` page.
- Verify mobile layout, playback, GitHub links, and reduced-motion behavior.
- Publish checksums and signatures for executable releases.
- Enable GitHub private vulnerability reporting.
- Keep the real-run date and canary-test disclosure adjacent to the metrics.
- Do not advertise the Windows installer or automatic patch executor before release.
