# CyberHawk Zero Trust - Campaign Creative

This is advertising copy, not bundled adware. The product should never install marketing software, collect telemetry by default, or interrupt users with promotions.

## Campaign platform

**Theme:** Your lockfile is evidence. Treat it that way.

**Hero headline:**

> Trust nothing in the dependency chain. Especially the instructions.

**Subhead:**

> CyberHawk is an open-source vulnerability watchdog that inventories local projects, checks packages against live disclosures, verifies what it can, quarantines what it cannot, and turns remediation into a human-approved workflow.

**Primary CTA:** Run a local audit<br>
**Secondary CTA:** Inspect the source

**Trust strip:** Open source / local dashboard / report-only by default / no source upload

## Software description

### 25 words

CyberHawk is a local, open-source dependency watchdog that persists vulnerability findings, evaluates package evidence, and proposes constrained fixes for human approval.

### 50 words

Point CyberHawk at a development folder. It imports OSV findings, evaluates npm lockfiles under an explicit zero-trust policy, preserves remediation state across scans, and generates a private local dashboard. Packages with active scripts or incomplete evidence are quarantined or sent to review—not silently trusted.

### One-line profile description

CyberHawk: an open-source vulnerability-response workflow that cross-references project dependencies with live disclosures, verifies artifact evidence, and proposes constrained patches with human approval.

## LinkedIn launch post

Your dependency scanner can tell you a package has a CVE.

It usually cannot tell you whether the artifact should be trusted, whether advisory text tried to steer an AI agent, whether an automated fix crossed a boundary, or whether the finding stayed fixed two scans later.

That is the gap we are building CyberHawk to close.

We ran the open-source prototype across a real Windows development portfolio:

- 27,474 package occurrences inspected
- 2,530 project/package/advisory findings persisted
- 25,816 exact locked artifacts admitted under policy
- 2,123 package records sent to review
- 243 packages with lifecycle scripts quarantined from automation
- 0 publishers falsely labeled “trusted”

We also verified the local scanner against its official release digest and tripped a harmless localhost canary to prove the alert path. The hit returned a `404` to the caller and appeared as a critical event in the local dashboard.

CyberHawk is report-only today. It proposes typed, human-approved remediation requests; it does not silently run package scripts or push changes. Next comes a sandboxed executor that must earn the right to make each change.

The engine, policy, dashboard, and tests are being built in the open.

Trust nothing. Verify everything. Trap unauthorized automation.

[View the results] [Inspect the source]

## Paid social variants

### Ad 1 - The challenge

**Headline:** Your scanner found a CVE. Now what?

**Body:** CyberHawk turns local dependency findings into persistent, reviewable action—without turning advisory prose into shell commands. Open source. Report-only by default.

**CTA:** See the local test

### Ad 2 - The zero-trust angle

**Headline:** A checksum is evidence. It is not trust.

**Body:** CyberHawk admits exact locked artifacts, quarantines lifecycle scripts, records unknown publisher provenance, and keeps the human in control of every proposed fix.

**CTA:** Inspect the policy

### Ad 3 - The AI security angle

**Headline:** What if your security data talks back to your agent?

**Body:** Treat package metadata and advisory text as hostile input. CyberHawk detects steering patterns, emits typed remediation requests, and supports harmless canaries that reveal unexpected automation.

**CTA:** Watch the canary demo

### Ad 4 - The SMB angle

**Headline:** Vulnerability response without the enterprise rollout.

**Body:** Scan local code folders, preserve findings across runs, and give a small cyber team one private dashboard for what is open, under review, quarantined, or verified fixed.

**CTA:** Run it locally

## Short display copy

| Headline | Supporting line |
|---|---|
| Your lockfile is evidence. | CyberHawk reads it like an investigator. |
| CVEs change. Your dashboard should too. | Persistent local vulnerability response. |
| Do not let an advisory become a command. | Typed requests. Human approval. |
| `npm install` is not a remediation strategy. | Verify, quarantine, review, then act. |
| The package is pinned. The publisher is still unknown. | Zero trust for the dependency chain. |
| A clean scan is an observation, not absolution. | CyberHawk requires repeated evidence to close. |

## 30-second demo script

**0-5 seconds:** Pan across a folder containing many projects.<br>
“Most of our code does not live in one perfect repository.”

**5-11 seconds:** Start the local scan and open the dashboard.<br>
“CyberHawk turns a folder into a persistent vulnerability-response queue.”

**11-18 seconds:** Show `ALLOW_LOCKED`, `REVIEW`, and `QUARANTINE`.<br>
“It separates what the lockfile proves from what still needs trust evidence.”

**18-24 seconds:** Open a typed remediation request.<br>
“Recommendations cross a narrow data boundary. The human still owns the change.”

**24-27 seconds:** Trigger the controlled canary; show the critical banner.<br>
“And if automation touches a boundary marker, CyberHawk records it.”

**27-30 seconds:** Logo and CTA.<br>
“Trust nothing. Verify everything. Run CyberHawk locally.”

## Screenshot captions for pickbits.ai/cyberhawk

Use the dashboard's `?view=public` mode for screenshots. It hides project names, target paths, detailed findings, and canary markers while retaining aggregate evidence.

1. **One local view of the backlog.** Findings persist across scans instead of disappearing into terminal output.
2. **Trust is a state, not a badge.** Exact locked artifacts can be admitted while publisher provenance remains unknown.
3. **Active content goes to quarantine.** Lifecycle scripts never earn automatic execution from a lockfile entry.
4. **Fixes must survive verification.** A missing finding remains pending until a second complete scan confirms closure.
5. **The trap works.** This critical event is a deliberately triggered localhost canary—not an attack claim.

## Claims boundary

Use “known-vulnerability detection,” “artifact evidence,” “defensive canary,” and “human-approved remediation.” Avoid “safe package,” “malware protection,” “fully trusted,” “autonomous patching,” or “prompt-injection prevention” until the corresponding proof exists. Always label the published canary hit as a controlled test and the July 22 figures as a point-in-time local run.
