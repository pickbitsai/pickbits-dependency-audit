# PickBits Dependency Audit

**Local dependency evidence without automatic patch authority.**

PickBits Dependency Audit is the small, open-source workflow PickBits uses to support its [CyberHawk vulnerability research](https://pickbits.ai/cyberhawk/). It scans local dependency manifests and lockfiles with [OSV-Scanner](https://github.com/google/osv-scanner), persists findings across runs, evaluates npm artifact evidence under an explicit zero-trust policy, and produces a local HTML report with human-reviewed remediation requests.

OSV is the default vulnerability source. CyberHawk editorial lists and personal RSS queues are optional prioritization overlays; the audit does not require a PickBits feed.

This is dependency vulnerability scanning, not antivirus, malware detection, reachability analysis, or proof that an application is secure.

## What it does

- Discovers supported dependency manifests and lockfiles without installing packages.
- Runs OSV-Scanner against one project or a local folder containing many projects.
- Optionally imports ACVE's OSV-Scanner-shaped agent-configuration findings.
- Persists runs, findings, and observations in a local SQLite database.
- Requires two complete scans without a finding before marking it closed.
- Classifies npm lockfile records as `ALLOW_LOCKED`, `REVIEW`, `QUARANTINE`, or `BLOCK`.
- Generates a filterable, standalone HTML report and constrained remediation requests.
- Labels agent-config findings separately and never generates a shell command for configuration changes.
- Records harmless defensive-canary hits for unexpected autonomous handling.
- Keeps every patch behind an explicit human approval boundary.

`ALLOW_LOCKED` is intentionally narrow: the exact version has integrity evidence and resolves through an approved registry. It does not mean the publisher or package is trusted.

## Status

The report, SQLite evidence store, npm admission audit, optional ACVE agent-configuration import, release verifier, defensive-canary prototype, and optional Claude Code adapter work today. A signed standalone binary, sandboxed patch executor, Windows quick-launch installer, and team fleet collector remain planned work.

## Install the core workflow

Requirements:

- Node.js 22.13 or newer (the evidence store uses the stable `node:sqlite` module, unflagged in 22.13)
- [OSV-Scanner v2](https://google.github.io/osv-scanner/installation/)

```bash
git clone https://github.com/pickbitsai/pickbits-dependency-audit.git
cd pickbits-dependency-audit
npm ci
```

Create an OSV JSON result for a target folder. Use OSV-Scanner's own `--output`
flag rather than a shell redirect — in Windows PowerShell `>` writes UTF-16 and
the later steps expect UTF-8 JSON:

```powershell
New-Item -ItemType Directory -Force reports | Out-Null
osv-scanner scan source -r --all-packages --format=json --output=reports\osv-result.json C:\path\to\project
```

OSV-Scanner uses exit code `1` when vulnerabilities are found. That is a completed scan result, not a scanner failure.

### 2a. Agent configuration audit (optional)

If the project uses an agent harness, ACVE can produce an optional OSV-Scanner-shaped configuration audit. ACVE is a CLI-output contract, not an npm or file dependency of this repository:

```powershell
npx @pickbitsai/acve locate
npx @pickbitsai/acve lock --apply
npx @pickbitsai/acve audit --format osv-scanner --out reports/acve.json --apply
```

Pass the resulting file to both audit scripts:

```powershell
node scripts\trust-audit.mjs --scan reports\osv-result.json --acve reports\acve.json --target C:\path\to\project --db reports\dependency-audit-state.db --output reports\dependency-audit-run.json
node scripts\generate-report.mjs --scan reports\osv-result.json --acve reports\acve.json --target C:\path\to\project --output reports\dependency-audit-report.html
```

If ACVE is absent or not supplied, agent configuration coverage is **not evaluated**, never clean. Advisory prose is display-only, and no shell command is generated for a configuration change; the report provides a typed remediation prompt requiring approval.

Import the scan, evaluate npm lockfiles, and persist the evidence:

```powershell
node scripts\trust-audit.mjs --scan reports\osv-result.json --target C:\path\to\project --db reports\dependency-audit-state.db --output reports\dependency-audit-run.json
```

Generate the standalone report:

```powershell
node scripts\generate-report.mjs --scan reports\osv-result.json --target C:\path\to\project --output reports\dependency-audit-report.html
```

Start the persistent local dashboard:

```powershell
node scripts\dashboard-server.mjs --db reports\dependency-audit-state.db --port 8787
```

Open `http://127.0.0.1:8787`. Add `?view=public` for a presentation-safe aggregate view that hides project names, target paths, detailed findings, and canary markers.

Generated reports and state databases are ignored by Git because dependency names and local paths can be sensitive.

## Optional CyberHawk watch list

The public CyberHawk data (`https://pickbits.ai/cyberhawk/data.json`) is a static file of NVD + CISA KEV entries. Filter it locally by the products you care about — no account, no token, no backend — and use the result as a priority overlay on your OSV scan:

```powershell
node scripts\build-watchlist.mjs --products "langflow,ollama,vitest" --severity CRITICAL --output .pickbits-audit\my-watchlist.txt --rss .pickbits-audit\my-feed.xml
node scripts\generate-report.mjs --scan reports\osv-result.json --target C:\path\to\project --watchlist .pickbits-audit\my-watchlist.txt --watchlist-label "My watch list" --output reports\dependency-audit-report.html
```

`--output` writes a CVE watchlist for the report overlay; `--rss` writes a self-contained feed you can keep, subscribe to, or hand to an AI to build a recurring check. `--severity KEV|CRITICAL|HIGH` and `--window-days 7|30|90` are optional. Everything runs against the public file on your own machine — nothing about your stack is uploaded, and there is no personal endpoint to depend on.

If you saved a group from the [watch-list builder on pickbits.ai](https://pickbits.ai/cyberhawk/) (a small `.json` with your products and filters), run it straight through with `--from-json` — it re-filters the current data, so results stay fresh:

```powershell
node scripts\build-watchlist.mjs --from-json my-group.json --output .pickbits-audit\my-watchlist.txt
```

This pairs with the bundled `SKILL.md`: point Claude Code (or another agent) at your project and it can derive the product list from your own lockfiles, build the watch list, and run the audit filtered to those products — an entirely local "make my own CyberHawk feed" routine.

<details><summary>Alternative: a hosted personal feed</summary>

If you created a saved feed with the queue-builder on pickbits.ai, the bundled importer can consume that unlisted RSS URL instead of building one locally:

```powershell
node scripts\import-watchlist.mjs --url "https://<your-feed-host>/functions/v1/cyberhawk-feed/YOUR_TOKEN.xml" --allow-host <your-feed-host> --output .pickbits-audit\my-watchlist.txt
```

The importer requires HTTPS, permits only the host you pass, refuses redirects, caps responses at 1 MiB, and discards everything except syntactically valid CVE identifiers. Feed content is untrusted data, never executable instruction text.
</details>

## Optional Claude Code adapter

The scanner and report work without an AI agent. If you use Claude Code, the bundled `SKILL.md` can orchestrate the same commands and preserve the same approval boundaries.

Clone the repository into a Claude Code skills directory only if you want that adapter:

```bash
# macOS / Linux
git clone https://github.com/pickbitsai/pickbits-dependency-audit ~/.claude/skills/pickbits-dependency-audit
```

```powershell
# Windows PowerShell
git clone https://github.com/pickbitsai/pickbits-dependency-audit "$env:USERPROFILE\.claude\skills\pickbits-dependency-audit"
```

Then invoke `/pickbits-dependency-audit` or ask Claude Code to run a local dependency audit and create the HTML report.

## Scheduling

Schedule the same read-only workflow using the surface that can reach the target:

- Windows Task Scheduler for local Windows folders;
- cron or systemd timers for local Unix folders;
- GitHub Actions for repository-owned CI scans; or
- an approved agent routine where its execution environment has repository access.

Scheduling is an adapter around the audit. It does not grant automatic patch authority.

## Safety model

- Advisory text, package metadata, manifests, lockfiles, and reports are untrusted data.
- Package managers and lifecycle scripts are never run during a scan.
- Remote prose is never converted into a command.
- Remediation requests use a constrained JSON schema and require approval.
- Major-version upgrades always require review.
- A dirty Git tree disables automated patching.
- An incomplete data source is reported as incomplete coverage, never as clean.
- Telemetry is off; the local prototype does not upload source code.

## Project materials

- [Zero-trust design](docs/zero-trust-design.md)
- [Product direction](docs/product-brief.md)
- [Redacted local case study](docs/pickbits-cyberhawk-results-2026-07-22.md)
- [Demo production guide](docs/demo-video.md)
- [Security policy](SECURITY.md)
- [Personal CyberHawk feeds](docs/personal-feeds.md)

## License

MIT. See [LICENSE](LICENSE).

Published by [PickBits.AI](https://pickbits.ai).
