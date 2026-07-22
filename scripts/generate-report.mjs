import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { canonicalRemediationRequest, safePackageName, safeVersion } from "./lib/trust.mjs";

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) continue;
    const key = item.slice(2);
    values[key] = argv[index + 1];
    index += 1;
  }
  return values;
}

const args = parseArgs(process.argv.slice(2));
const required = ["scan", "target", "output"];
for (const key of required) {
  if (!args[key]) {
    console.error(`Missing --${key}`);
    process.exit(2);
  }
}

const target = path.resolve(args.target);
const scanPath = path.resolve(args.scan);
const outputPath = path.resolve(args.output);
const watchlistPath = args.watchlist ? path.resolve(args.watchlist) : null;
const weeklyOsvDir = args["watchlist-osv-dir"] ? path.resolve(args["watchlist-osv-dir"]) : null;
const weekLabel = args["watchlist-label"] || (watchlistPath ? path.basename(watchlistPath) : "No external watchlist");
const scan = JSON.parse(fs.readFileSync(scanPath, "utf8"));
const watchlistText = watchlistPath ? fs.readFileSync(watchlistPath, "utf8") : "";
const weeklyCves = [...new Set(watchlistText.match(/CVE-\d{4}-\d{4,7}/g) || [])].sort();

const severityRank = { CRITICAL: 5, HIGH: 4, MODERATE: 3, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
const severityLabel = (value) => {
  const normalized = String(value || "UNKNOWN").toUpperCase();
  return normalized === "MEDIUM" ? "MODERATE" : severityRank[normalized] ? normalized : "UNKNOWN";
};

function cleanVersion(value) {
  return String(value || "").trim().replace(/^v(?=\d)/i, "");
}

function versionParts(value) {
  const cleaned = cleanVersion(value);
  const [core, prerelease = ""] = cleaned.split("-", 2);
  return {
    raw: cleaned,
    core: core.split(/[.+]/).map((part) => (/^\d+$/.test(part) ? Number(part) : part)),
    prerelease,
  };
}

function compareVersions(leftValue, rightValue) {
  const left = versionParts(leftValue);
  const right = versionParts(rightValue);
  const length = Math.max(left.core.length, right.core.length);
  for (let index = 0; index < length; index += 1) {
    const a = left.core[index] ?? 0;
    const b = right.core[index] ?? 0;
    if (typeof a === "number" && typeof b === "number" && a !== b) return a < b ? -1 : 1;
    if (String(a) !== String(b)) return String(a).localeCompare(String(b), undefined, { numeric: true });
  }
  if (!left.prerelease && right.prerelease) return 1;
  if (left.prerelease && !right.prerelease) return -1;
  return left.prerelease.localeCompare(right.prerelease, undefined, { numeric: true });
}

function majorOf(value) {
  const match = cleanVersion(value).match(/^(\d+)/);
  return match ? Number(match[1]) : null;
}

function minorOf(value) {
  const match = cleanVersion(value).match(/^\d+\.(\d+)/);
  return match ? Number(match[1]) : null;
}

function upgradeType(installed, fixed) {
  if (!fixed) return "unverified";
  const installedMajor = majorOf(installed);
  const fixedMajor = majorOf(fixed);
  if (installedMajor === null || fixedMajor === null) return "review";
  if (installedMajor !== fixedMajor) return "major";
  return minorOf(installed) === minorOf(fixed) ? "patch" : "minor";
}

function fixedVersions(vulnerability, packageInfo) {
  const matches = [];
  for (const affected of vulnerability.affected || []) {
    const affectedPackage = affected.package;
    if (affectedPackage?.name && affectedPackage.name.toLowerCase() !== packageInfo.name.toLowerCase()) continue;
    if (affectedPackage?.ecosystem && packageInfo.ecosystem && affectedPackage.ecosystem.toLowerCase() !== packageInfo.ecosystem.toLowerCase()) continue;
    for (const range of affected.ranges || []) {
      const events = range.database_specific?.extracted_events || range.events || [];
      for (const event of events) if (event.fixed) matches.push(cleanVersion(event.fixed));
    }
  }
  return [...new Set(matches)].filter(Boolean);
}

function chooseFix(installed, candidates) {
  const newer = candidates.filter((candidate) => compareVersions(candidate, installed) > 0);
  if (!newer.length) return null;
  const sameMajor = newer.filter((candidate) => majorOf(candidate) === majorOf(installed));
  return (sameMajor.length ? sameMajor : newer).sort(compareVersions)[0];
}

function normalizeSource(source) {
  return path.win32.normalize(String(source || "").replaceAll("/", "\\"));
}

function relativeSource(source) {
  const normalized = normalizeSource(source);
  const relative = path.win32.relative(path.win32.normalize(target), normalized);
  return relative && !relative.startsWith("..") ? relative : normalized;
}

function projectFromSource(source) {
  const relative = relativeSource(source);
  return relative.split(/[\\/]/)[0] || "(root)";
}

const manifestCache = new Map();
function readJsonIfPresent(filePath) {
  if (manifestCache.has(filePath)) return manifestCache.get(filePath);
  let parsed = null;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {}
  manifestCache.set(filePath, parsed);
  return parsed;
}

function dependencyContext(source, packageInfo) {
  const normalized = normalizeSource(source);
  const directory = path.win32.dirname(normalized);
  const filename = path.win32.basename(normalized).toLowerCase();
  const packageJsonPath = path.win32.join(directory, "package.json");
  const packageJson = readJsonIfPresent(packageJsonPath);
  if (packageJson) {
    for (const [section, kind] of [
      ["dependencies", "runtime"],
      ["devDependencies", "development"],
      ["optionalDependencies", "optional"],
      ["peerDependencies", "peer"],
    ]) {
      if (Object.hasOwn(packageJson[section] || {}, packageInfo.name)) {
        return { direct: true, kind, manifest: relativeSource(packageJsonPath), manager: filename.startsWith("pnpm") ? "pnpm" : filename === "yarn.lock" ? "yarn" : "npm" };
      }
    }
    return { direct: false, kind: "transitive", manifest: relativeSource(packageJsonPath), manager: filename.startsWith("pnpm") ? "pnpm" : filename === "yarn.lock" ? "yarn" : "npm" };
  }
  if (filename === "requirements.txt") {
    try {
      const normalizedName = packageInfo.name.toLowerCase().replaceAll("_", "-");
      const direct = fs.readFileSync(normalized, "utf8").split(/\r?\n/).some((line) => {
        const candidate = line.trim().split(/[<>=!~;\[]/, 1)[0].trim().toLowerCase().replaceAll("_", "-");
        return candidate === normalizedName;
      });
      return { direct, kind: direct ? "runtime" : "unknown", manifest: relativeSource(normalized), manager: "pip" };
    } catch {}
  }
  if (filename === "cargo.lock") {
    const cargoToml = path.win32.join(directory, "Cargo.toml");
    try {
      const text = fs.readFileSync(cargoToml, "utf8");
      const direct = new RegExp(`^\\s*["']?${packageInfo.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']?\\s*=`, "mi").test(text);
      return { direct, kind: direct ? "runtime" : "transitive", manifest: relativeSource(cargoToml), manager: "cargo" };
    } catch {}
  }
  return { direct: false, kind: "unknown", manifest: relativeSource(normalized), manager: packageInfo.ecosystem?.toLowerCase() || "unknown" };
}

function commandFor(context, packageInfo, fixed, type) {
  if (!context.direct || !fixed || type === "major" || !safePackageName(packageInfo.name, packageInfo.ecosystem) || !safeVersion(fixed)) return null;
  const spec = `${packageInfo.name}@${fixed}`;
  if (context.manager === "npm") return `npm install --ignore-scripts --save-exact "${spec}"`;
  if (context.manager === "pnpm") return `pnpm add --ignore-scripts --save-exact "${spec}"`;
  if (context.manager === "yarn") return `yarn add --ignore-scripts --exact "${spec}"`;
  if (context.manager === "cargo") return `cargo update -p "${packageInfo.name}" --precise "${fixed}"`;
  return null;
}

function cveFor(vulnerability) {
  if (/^CVE-/.test(vulnerability.id || "")) return vulnerability.id;
  return (vulnerability.aliases || []).find((alias) => /^CVE-/.test(alias)) || null;
}

function findingId(parts) {
  return crypto.createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 16);
}

const findings = [];
const inventory = [];
const sourceFiles = new Set();
const packageCoordinates = new Set();
for (const result of scan.results || []) {
  const source = result.source?.path || result.source || "unknown";
  sourceFiles.add(relativeSource(source));
  for (const packageGroup of result.packages || []) {
    const packageInfo = packageGroup.package || {};
    if (!packageInfo.name || !packageInfo.version) continue;
    const inventoryItem = {
      source,
      project: projectFromSource(source),
      name: packageInfo.name,
      version: packageInfo.version,
      ecosystem: packageInfo.ecosystem || "unknown",
    };
    inventory.push(inventoryItem);
    packageCoordinates.add(`${inventoryItem.ecosystem}\u0000${inventoryItem.name}\u0000${inventoryItem.version}`);
    for (const vulnerability of packageGroup.vulnerabilities || []) {
      const context = dependencyContext(source, packageInfo);
      const cve = cveFor(vulnerability);
      const candidates = fixedVersions(vulnerability, packageInfo);
      const fixed = chooseFix(packageInfo.version, candidates);
      const type = upgradeType(packageInfo.version, fixed);
      const weekly = weeklyCves.includes(vulnerability.id) || (vulnerability.aliases || []).some((alias) => weeklyCves.includes(alias));
      const severity = severityLabel(vulnerability.database_specific?.severity);
      const command = commandFor(context, packageInfo, fixed, type);
      const project = projectFromSource(source);
      const finding = {
        id: findingId([source, packageInfo.ecosystem, packageInfo.name, packageInfo.version, vulnerability.id]),
        project,
        source: relativeSource(source),
        manifest: context.manifest,
        package: packageInfo.name,
        installed: packageInfo.version,
        ecosystem: packageInfo.ecosystem || "unknown",
        advisory: vulnerability.id,
        cve,
        summary: String(vulnerability.summary || vulnerability.details || "Known vulnerability").replace(/\s+/g, " ").slice(0, 240),
        severity,
        fixed,
        upgrade: type,
        weekly,
        supplemental: false,
        direct: context.direct,
        dependencyKind: context.kind,
        command,
        osvUrl: `https://osv.dev/vulnerability/${encodeURIComponent(vulnerability.id)}`,
      };
      finding.request = canonicalRemediationRequest(finding);
      finding.prompt = JSON.stringify(finding.request, null, 2);
      findings.push(finding);
    }
  }
}

function affectedByEvents(version, events) {
  if (!events?.length) return null;
  let affected = false;
  let comparable = false;
  for (const event of events) {
    if (event.introduced !== undefined) {
      comparable = true;
      const introduced = event.introduced === "0" ? "0" : cleanVersion(event.introduced);
      if (compareVersions(version, introduced) >= 0) affected = true;
    }
    if (event.fixed !== undefined) {
      comparable = true;
      if (compareVersions(version, cleanVersion(event.fixed)) >= 0) affected = false;
    }
    if (event.last_affected !== undefined) {
      comparable = true;
      affected = compareVersions(version, cleanVersion(event.last_affected)) <= 0;
    }
  }
  return comparable ? affected : null;
}

function weeklySupplementalAudit() {
  const nativeMatches = new Set(findings.filter((item) => item.weekly).flatMap((item) => [item.cve, item.advisory].filter(Boolean)));
  const audit = { checkedNotPresent: [], notAffected: [], unresolved: [], supplemental: [] };
  if (!weeklyOsvDir) {
    audit.unresolved.push(...weeklyCves);
    return audit;
  }
  for (const cve of weeklyCves) {
    if (nativeMatches.has(cve)) continue;
    const advisoryPath = path.join(weeklyOsvDir, `osv-${cve}.json`);
    let advisory;
    try {
      advisory = JSON.parse(fs.readFileSync(advisoryPath, "utf8"));
    } catch {
      audit.unresolved.push(cve);
      continue;
    }
    const identities = new Set();
    for (const affected of advisory.affected || []) {
      if (affected.package?.name) identities.add(affected.package.name.toLowerCase());
      for (const range of affected.ranges || []) {
        if (range.repo) identities.add(path.posix.basename(new URL(range.repo).pathname).replace(/\.git$/i, "").toLowerCase());
      }
    }
    for (const reference of advisory.references || []) {
      if (reference.type !== "PACKAGE") continue;
      try { identities.add(path.posix.basename(new URL(reference.url).pathname).replace(/\.git$/i, "").toLowerCase()); } catch {}
    }
    if (!identities.size) {
      audit.unresolved.push(cve);
      continue;
    }
    const candidates = inventory.filter((item) => identities.has(item.name.toLowerCase()));
    if (!candidates.length) {
      audit.checkedNotPresent.push(cve);
      continue;
    }
    let mapped = false;
    let comparable = false;
    for (const item of candidates) {
      for (const affected of advisory.affected || []) {
        if (affected.package?.name && affected.package.name.toLowerCase() !== item.name.toLowerCase()) continue;
        const exact = (affected.versions || []).some((version) => cleanVersion(version) === cleanVersion(item.version));
        let state = exact ? true : null;
        for (const range of affected.ranges || []) {
          const events = range.database_specific?.extracted_events || (range.type !== "GIT" ? range.events : null);
          const result = affectedByEvents(item.version, events);
          if (result !== null) {
            comparable = true;
            state = result;
          }
        }
        if (exact) comparable = true;
        if (state !== true) continue;
        mapped = true;
        const packageInfo = { name: item.name, version: item.version, ecosystem: item.ecosystem };
        const context = dependencyContext(item.source, packageInfo);
        const fixes = [];
        for (const range of affected.ranges || []) {
          for (const event of range.database_specific?.extracted_events || []) if (event.fixed) fixes.push(cleanVersion(event.fixed));
        }
        const fixed = chooseFix(item.version, fixes);
        const type = upgradeType(item.version, fixed);
        const command = commandFor(context, packageInfo, fixed, type);
        const finding = {
          id: findingId([item.source, item.ecosystem, item.name, item.version, cve, "supplemental"]),
          project: item.project,
          source: relativeSource(item.source),
          manifest: context.manifest,
          package: item.name,
          installed: item.version,
          ecosystem: item.ecosystem,
          advisory: advisory.id,
          cve,
          summary: String(advisory.summary || "Local watchlist vulnerability").replace(/\s+/g, " ").slice(0, 240),
          severity: severityLabel(advisory.database_specific?.severity),
          fixed,
          upgrade: type,
          weekly: true,
          supplemental: true,
          direct: context.direct,
          dependencyKind: context.kind,
          command,
          osvUrl: `https://osv.dev/vulnerability/${encodeURIComponent(cve)}`,
        };
        finding.request = canonicalRemediationRequest(finding);
        finding.prompt = JSON.stringify(finding.request, null, 2);
        findings.push(finding);
        audit.supplemental.push(cve);
      }
    }
    if (!mapped) (comparable ? audit.notAffected : audit.unresolved).push(cve);
  }
  for (const key of Object.keys(audit)) audit[key] = [...new Set(audit[key])].sort();
  return audit;
}

const weeklyAudit = weeklySupplementalAudit();
findings.sort((left, right) =>
  Number(right.weekly) - Number(left.weekly) ||
  severityRank[right.severity] - severityRank[left.severity] ||
  left.project.localeCompare(right.project) ||
  left.package.localeCompare(right.package)
);

const projectNames = [...new Set([...sourceFiles].map((source) => source.split(/[\\/]/)[0]))].sort((a, b) => a.localeCompare(b));
const affectedProjects = new Set(findings.map((item) => item.project));
const severityCounts = Object.fromEntries(["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"].map((severity) => [severity, findings.filter((item) => item.severity === severity).length]));
const actionable = findings.filter((item) => item.fixed && item.upgrade !== "major");
const directlyActionable = actionable.filter((item) => item.direct);
const reportId = crypto.createHash("sha256").update(`${target}|${weekLabel}|${fs.statSync(scanPath).mtimeMs}`).digest("hex").slice(0, 12);
const generatedAt = new Date().toISOString();
const report = {
  meta: {
    reportId,
    target,
    generatedAt,
    watchlistLabel: weekLabel,
    scanEngine: "OSV-Scanner 2.4.0",
    scanMode: "read-only, explicit lockfiles, no dependency resolution",
    sourceFiles: sourceFiles.size,
    projects: projectNames.length,
    packageOccurrences: inventory.length,
    uniquePackageCoordinates: packageCoordinates.size,
    affectedProjects: affectedProjects.size,
  },
  summary: {
    findings: findings.length,
    severityCounts,
    watchlistConfirmed: findings.filter((item) => item.weekly && !item.supplemental).length,
    watchlistSupplemental: findings.filter((item) => item.weekly && item.supplemental).length,
    actionable: actionable.length,
    directlyActionable: directlyActionable.length,
  },
  watchlist: { cves: weeklyCves, ...weeklyAudit },
  projects: projectNames,
  findings,
};

const embedded = JSON.stringify(report).replaceAll("<", "\\u003c").replaceAll("\u2028", "\\u2028").replaceAll("\u2029", "\\u2029");
const html = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>PickBits Dependency Audit — ${escapeHtml(target)}</title>
<style>
:root{--bg:#07110f;--panel:#0d1917;--panel2:#11221e;--line:#1f3a33;--text:#e8f2ed;--muted:#8da99e;--mint:#4ce5a3;--mint2:#9af7cf;--red:#ff5d73;--orange:#ff9f43;--yellow:#e9d758;--blue:#65b8ff;--shadow:0 18px 60px rgba(0,0,0,.28)}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 80% 0,rgba(76,229,163,.08),transparent 28rem),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}button,input,select{font:inherit}button{cursor:pointer}.shell{max-width:1500px;margin:auto;padding:0 28px 64px}.topbar{height:72px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);position:sticky;top:0;background:rgba(7,17,15,.92);backdrop-filter:blur(16px);z-index:20}.brand{font-weight:800;letter-spacing:.12em}.brand b{color:var(--mint)}.brand span{color:var(--muted);font-weight:500;font-size:11px;margin-left:12px}.top-actions{display:flex;gap:10px;align-items:center}.button{border:1px solid var(--line);border-radius:9px;background:var(--panel);color:var(--text);padding:9px 13px;display:inline-flex;gap:8px;align-items:center;text-decoration:none}.button:hover{border-color:#376458;background:var(--panel2)}.button.primary{background:var(--mint);border-color:var(--mint);color:#042116;font-weight:750}.button:disabled{opacity:.45;cursor:not-allowed}.queue-count{background:#042116;color:var(--mint2);border-radius:999px;padding:1px 7px;font-size:12px}.hero{display:grid;grid-template-columns:1.45fr .75fr;gap:22px;padding:44px 0 22px}.eyebrow{color:var(--mint);text-transform:uppercase;letter-spacing:.16em;font:700 11px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace}.hero h1{font-size:clamp(34px,5vw,62px);line-height:1.02;letter-spacing:-.045em;margin:10px 0 15px;max-width:840px}.hero p{color:var(--muted);font-size:17px;max-width:720px;margin:0}.scope{background:linear-gradient(145deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:15px;padding:20px;box-shadow:var(--shadow)}.scope-row{display:flex;justify-content:space-between;gap:20px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.05)}.scope-row:last-child{border:0}.scope-row span{color:var(--muted)}.scope-row strong{text-align:right;max-width:58%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.cards{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:16px 0 22px}.card{border:1px solid var(--line);background:var(--panel);border-radius:13px;padding:17px;min-height:118px}.card .label{color:var(--muted);font-size:12px}.card .value{font-size:31px;font-weight:780;letter-spacing:-.04em;margin:7px 0 1px}.card .note{font-size:11px;color:var(--muted)}.card.critical .value{color:var(--red)}.card.high .value{color:var(--orange)}.card.weekly .value,.card.action .value{color:var(--mint)}.notice{display:flex;gap:14px;align-items:flex-start;border:1px solid #275847;background:rgba(76,229,163,.06);padding:16px 18px;border-radius:12px;margin-bottom:22px}.notice.warn{border-color:#6c5e2b;background:rgba(233,215,88,.06)}.notice strong{display:block;margin-bottom:2px}.notice p{margin:0;color:var(--muted)}.dot{width:10px;height:10px;border-radius:50%;background:var(--mint);box-shadow:0 0 18px var(--mint);margin-top:6px;flex:none}.notice.warn .dot{background:var(--yellow);box-shadow:0 0 18px var(--yellow)}.section{margin-top:30px}.section-head{display:flex;align-items:end;justify-content:space-between;margin:0 0 13px}.section h2{margin:0;font-size:20px;letter-spacing:-.02em}.section-sub{color:var(--muted);font-size:12px}.filters{display:grid;grid-template-columns:minmax(250px,1fr) repeat(3,minmax(140px,190px));gap:9px;background:var(--panel);border:1px solid var(--line);padding:12px;border-radius:12px 12px 0 0}.control{width:100%;background:#091512;border:1px solid var(--line);color:var(--text);border-radius:8px;padding:10px 11px;outline:none}.control:focus{border-color:var(--mint)}.table-wrap{border:1px solid var(--line);border-top:0;border-radius:0 0 12px 12px;overflow:hidden;background:var(--panel)}table{width:100%;border-collapse:collapse}th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.09em;background:#091512;padding:12px 14px;border-bottom:1px solid var(--line);position:sticky;top:72px;z-index:5}td{padding:13px 14px;border-bottom:1px solid rgba(255,255,255,.055);vertical-align:top}tr:hover td{background:rgba(255,255,255,.018)}.sev{display:inline-flex;border-radius:999px;padding:3px 8px;font-size:10px;font-weight:800;letter-spacing:.07em;border:1px solid}.sev.CRITICAL{color:#ff91a0;border-color:#71313c;background:#2b1117}.sev.HIGH{color:#ffc07e;border-color:#714d29;background:#281c10}.sev.MODERATE{color:#f4e67c;border-color:#6c6128;background:#27240e}.sev.LOW{color:#95ccff;border-color:#285479;background:#0d1e2c}.sev.UNKNOWN{color:#b6c4be;border-color:#3c4d46;background:#151d1a}.project{font-weight:700}.path,.muted{color:var(--muted);font-size:12px}.pkg{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.fix{color:var(--mint2);font-weight:700}.weekly-flag{display:inline-block;color:var(--mint);font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-top:5px}.actions{display:flex;gap:7px;flex-wrap:wrap;min-width:165px}.mini{border:1px solid var(--line);background:#091512;color:var(--text);border-radius:7px;padding:6px 8px;font-size:11px}.mini:hover{border-color:var(--mint)}.mini.queued{background:var(--mint);color:#042116;border-color:var(--mint);font-weight:800}.pagination{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;color:var(--muted)}.pages{display:flex;gap:7px}.empty{padding:50px;text-align:center;color:var(--muted)}.coverage-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.coverage-card{border:1px solid var(--line);background:var(--panel);border-radius:12px;padding:18px}.coverage-card h3{margin:0 0 12px}.coverage-list{display:grid;grid-template-columns:1fr auto;gap:8px;color:var(--muted)}.coverage-list strong{color:var(--text)}dialog{border:1px solid var(--line);border-radius:15px;background:var(--panel);color:var(--text);padding:0;width:min(760px,calc(100vw - 30px));max-height:85vh;box-shadow:0 30px 100px rgba(0,0,0,.65)}dialog::backdrop{background:rgba(0,0,0,.7);backdrop-filter:blur(3px)}.drawer-head{display:flex;justify-content:space-between;align-items:center;padding:18px 20px;border-bottom:1px solid var(--line)}.drawer-head h2{margin:0}.drawer-body{padding:10px 20px 18px;overflow:auto;max-height:58vh}.queue-item{border-bottom:1px solid var(--line);padding:14px 0}.queue-item strong{display:block}.queue-item code{display:block;background:#081310;color:var(--mint2);padding:9px;border-radius:7px;margin-top:8px;overflow:auto}.drawer-foot{display:flex;justify-content:space-between;gap:9px;padding:15px 20px;border-top:1px solid var(--line)}.toast{position:fixed;right:22px;bottom:22px;background:var(--mint);color:#042116;padding:11px 15px;border-radius:9px;font-weight:750;box-shadow:var(--shadow);opacity:0;transform:translateY(12px);pointer-events:none;transition:.2s;z-index:50}.toast.show{opacity:1;transform:translateY(0)}@media(max-width:1100px){.cards{grid-template-columns:repeat(3,1fr)}.hero{grid-template-columns:1fr}.filters{grid-template-columns:1fr 1fr}.hide-md{display:none}}@media(max-width:680px){.shell{padding:0 14px 40px}.cards{grid-template-columns:1fr 1fr}.filters{grid-template-columns:1fr}.coverage-grid{grid-template-columns:1fr}.topbar{height:auto;padding:13px 0}.brand span{display:none}.hero{padding-top:28px}.hide-sm{display:none}th{top:59px}.top-actions .button:not(.primary){display:none}}
</style>
</head>
<body>
<div class="shell">
  <header class="topbar">
    <div class="brand"><b>CYBER</b>HAWK <span>// LOCAL DEPENDENCY WATCHDOG</span></div>
    <div class="top-actions">
      <button class="button" id="exportTop">Export report</button>
      <button class="button primary" id="openQueue">Patch queue <span class="queue-count" id="queueCount">0</span></button>
    </div>
  </header>
  <main>
    <section class="hero">
      <div>
        <div class="eyebrow">Portfolio scan · live OSV advisories</div>
        <h1>Your dependency exposure, prioritized.</h1>
        <p>A real, read-only OSV scan of <strong>${escapeHtml(target)}</strong>, evaluated against structured vulnerability data. Queue typed remediation requests here; review and execution remain human-controlled.</p>
      </div>
      <aside class="scope">
        <div class="scope-row"><span>Generated</span><strong id="generatedAt"></strong></div>
        <div class="scope-row"><span>Engine</span><strong>${escapeHtml(report.meta.scanEngine)}</strong></div>
        <div class="scope-row"><span>Inputs</span><strong>${report.meta.sourceFiles} dependency files</strong></div>
        <div class="scope-row"><span>Projects</span><strong>${report.meta.projects}</strong></div>
        <div class="scope-row"><span>Mode</span><strong>Report only</strong></div>
      </aside>
    </section>
    <section class="cards">
      <article class="card critical"><div class="label">Critical findings</div><div class="value">${severityCounts.CRITICAL}</div><div class="note">Across project + package pairs</div></article>
      <article class="card high"><div class="label">High findings</div><div class="value">${severityCounts.HIGH}</div><div class="note">Review before lower severities</div></article>
      <article class="card weekly"><div class="label">Watchlist matches</div><div class="value">${report.summary.watchlistConfirmed + report.summary.watchlistSupplemental}</div><div class="note">${weeklyCves.length ? escapeHtml(weekLabel) : "Optional local input"}</div></article>
      <article class="card"><div class="label">Affected projects</div><div class="value">${report.meta.affectedProjects}</div><div class="note">Of ${report.meta.projects} scanned</div></article>
      <article class="card action"><div class="label">Verified fixes</div><div class="value">${report.summary.actionable}</div><div class="note">${report.summary.directlyActionable} direct dependencies</div></article>
      <article class="card"><div class="label">Known findings</div><div class="value">${report.summary.findings}</div><div class="note">Before reachability analysis</div></article>
    </section>
    <div class="notice ${report.summary.watchlistConfirmed + report.summary.watchlistSupplemental ? "warn" : ""}">
      <span class="dot"></span>
      <div><strong>${weeklyCves.length ? (report.summary.watchlistConfirmed + report.summary.watchlistSupplemental ? `${report.summary.watchlistConfirmed + report.summary.watchlistSupplemental} local watchlist matches need attention` : "No local watchlist CVEs were confirmed in the scanned package inventory") : "OSV findings prioritized without an external editorial feed"}</strong><p>${weeklyCves.length ? `${weeklyCves.length} CVEs from a user-supplied local watchlist were evaluated.` : "A local CVE watchlist can be supplied when a team has its own priority intelligence."} This does not erase the ${report.summary.findings} OSV findings shown below.</p></div>
    </div>
    <section class="section" id="findingsSection">
      <div class="section-head"><div><h2>Findings</h2><div class="section-sub" id="resultCount"></div></div><div class="section-sub">Select an item to build a human-approved patch plan.</div></div>
      <div class="filters">
        <input class="control" id="search" placeholder="Search project, package, CVE…" aria-label="Search findings">
        <select class="control" id="severity"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MODERATE</option><option>LOW</option><option>UNKNOWN</option></select>
        <select class="control" id="project"><option value="">All projects</option></select>
        <select class="control" id="actionability"><option value="">All findings</option><option value="weekly">Local watchlist</option><option value="fixed">Verified fix</option><option value="direct">Direct dependency</option><option value="queued">In patch queue</option></select>
      </div>
      <div class="table-wrap">
        <table><thead><tr><th>Severity</th><th>Project</th><th>Dependency</th><th class="hide-md">Advisory</th><th>Remediation</th><th>Actions</th></tr></thead><tbody id="rows"></tbody></table>
        <div class="pagination"><span id="pageLabel"></span><div class="pages"><button class="mini" id="previous">Previous</button><button class="mini" id="next">Next</button></div></div>
      </div>
    </section>
    <section class="section">
      <div class="section-head"><div><h2>Coverage and trust</h2><div class="section-sub">What this run did—and did not—prove.</div></div></div>
      <div class="coverage-grid">
        <article class="coverage-card"><h3>Scan coverage</h3><div class="coverage-list"><span>Dependency inputs</span><strong>${report.meta.sourceFiles}</strong><span>Package occurrences</span><strong>${report.meta.packageOccurrences.toLocaleString()}</strong><span>Unique package coordinates</span><strong>${report.meta.uniquePackageCoordinates.toLocaleString()}</strong><span>Local watchlist CVEs</span><strong>${weeklyCves.length}</strong><span>Watchlist mappings unresolved</span><strong>${report.watchlist.unresolved.length}</strong></div></article>
        <article class="coverage-card"><h3>Safety boundary</h3><p class="muted">This report did not install packages, execute lifecycle scripts, edit manifests, create branches, or push code. Requirements manifests were scanned without remote dependency resolution, so unpinned Python transitive coverage may be incomplete. Findings indicate known vulnerable components, not exploitability or malware.</p></article>
      </div>
    </section>
  </main>
</div>
<dialog id="queueDialog">
  <div class="drawer-head"><div><div class="eyebrow">Human approval boundary</div><h2>Patch queue</h2></div><button class="mini" id="closeQueue">Close</button></div>
  <div class="drawer-body" id="queueBody"></div>
  <div class="drawer-foot"><button class="button" id="clearQueue">Clear</button><div><button class="button" id="copyQueue">Copy typed requests</button> <button class="button primary" id="exportQueue">Export plan</button></div></div>
</dialog>
<div class="toast" id="toast"></div>
<script id="dependency-audit-data" type="application/json">${embedded}</script>
<script>
const report=JSON.parse(document.getElementById('dependency-audit-data').textContent);const pageSize=50;let page=1;const storageKey='pickbits-dependency-audit:'+report.meta.reportId;let queue=new Set(JSON.parse(localStorage.getItem(storageKey)||'[]'));const el=id=>document.getElementById(id);const projectSelect=el('project');for(const project of report.projects){const option=document.createElement('option');option.value=project;option.textContent=project;projectSelect.append(option)}el('generatedAt').textContent=new Date(report.meta.generatedAt).toLocaleString();function persist(){localStorage.setItem(storageKey,JSON.stringify([...queue]));el('queueCount').textContent=queue.size}function toast(message){const node=el('toast');node.textContent=message;node.classList.add('show');clearTimeout(window.toastTimer);window.toastTimer=setTimeout(()=>node.classList.remove('show'),2200)}function filtered(){const query=el('search').value.trim().toLowerCase(),severity=el('severity').value,project=el('project').value,action=el('actionability').value;return report.findings.filter(f=>(!query||[f.project,f.package,f.cve,f.advisory,f.summary].some(v=>String(v||'').toLowerCase().includes(query)))&&(!severity||f.severity===severity)&&(!project||f.project===project)&&(!action||(action==='weekly'&&f.weekly)||(action==='fixed'&&f.fixed)||(action==='direct'&&f.direct)||(action==='queued'&&queue.has(f.id))))}function tag(text,className){const span=document.createElement('span');span.className=className;span.textContent=text;return span}function render(){const data=filtered(),pages=Math.max(1,Math.ceil(data.length/pageSize));page=Math.min(page,pages);const start=(page-1)*pageSize,shown=data.slice(start,start+pageSize),body=el('rows');body.replaceChildren();for(const f of shown){const tr=document.createElement('tr');const severity=document.createElement('td');severity.append(tag(f.severity,'sev '+f.severity));if(f.weekly)severity.append(tag(f.supplemental?'weekly · supplemental':'weekly match','weekly-flag'));const project=document.createElement('td');project.append(tag(f.project,'project'));project.append(document.createElement('br'));project.append(tag(f.source,'path'));const dependency=document.createElement('td');dependency.append(tag(f.package,'pkg'));dependency.append(document.createElement('br'));dependency.append(tag(f.installed+' · '+f.ecosystem+(f.direct?' · direct':' · '+f.dependencyKind),'muted'));const advisory=document.createElement('td');advisory.className='hide-md';const link=document.createElement('a');link.href=f.osvUrl;link.target='_blank';link.rel='noopener noreferrer';link.className='pkg';link.style.color='var(--blue)';link.textContent=f.cve||f.advisory;advisory.append(link);advisory.append(document.createElement('br'));advisory.append(tag(f.summary,'muted'));const remediation=document.createElement('td');if(f.fixed){remediation.append(tag(f.installed+' → '+f.fixed,'fix'));remediation.append(document.createElement('br'));remediation.append(tag(f.upgrade+' upgrade'+(f.upgrade==='major'?' · review required':''),'muted'))}else{remediation.append(tag('No verified fixed version','muted'))}const actions=document.createElement('td');const wrap=document.createElement('div');wrap.className='actions';const queueButton=document.createElement('button');queueButton.className='mini '+(queue.has(f.id)?'queued':'');queueButton.textContent=queue.has(f.id)?'Queued ✓':(f.fixed&&f.upgrade!=='major'?'Queue patch':'Queue review');queueButton.onclick=()=>{queue.has(f.id)?queue.delete(f.id):queue.add(f.id);persist();render();toast(queue.has(f.id)?'Added to patch queue':'Removed from queue')};const copyButton=document.createElement('button');copyButton.className='mini';copyButton.textContent=f.command?'Copy command':'Copy prompt';copyButton.onclick=async()=>{await navigator.clipboard.writeText(f.command||f.prompt);toast(f.command?'Command copied':'Remediation prompt copied')};wrap.append(queueButton,copyButton);actions.append(wrap);tr.append(severity,project,dependency,advisory,remediation,actions);body.append(tr)}if(!shown.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=6;td.className='empty';td.textContent='No findings match these filters.';tr.append(td);body.append(tr)}el('resultCount').textContent=data.length.toLocaleString()+' matching findings';el('pageLabel').textContent='Page '+page+' of '+pages;el('previous').disabled=page<=1;el('next').disabled=page>=pages;persist()}function queuedFindings(){return report.findings.filter(f=>queue.has(f.id))}function renderQueue(){const body=el('queueBody'),items=queuedFindings();body.replaceChildren();if(!items.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='Nothing queued yet. Choose “Queue patch” or “Queue review” from a finding.';body.append(empty)}for(const f of items){const item=document.createElement('div');item.className='queue-item';item.append(tag(f.project+' · '+f.package+'@'+f.installed,'project'));item.append(tag((f.cve||f.advisory)+(f.fixed?' → '+f.fixed:' · no verified fix'),'muted'));if(f.command){const code=document.createElement('code');code.textContent=f.command;item.append(code)}body.append(item)}}function download(filename,value,type='application/json'){const blob=new Blob([value],{type});const url=URL.createObjectURL(blob);const anchor=document.createElement('a');anchor.href=url;anchor.download=filename;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),500)}function exportPlan(){const items=queuedFindings();download('dependency-audit-patch-plan-'+report.meta.reportId+'.json',JSON.stringify({schemaVersion:1,report:report.meta,approvedAt:new Date().toISOString(),status:'proposed-not-applied',items:items.map(({id,project,manifest,package:pkg,installed,fixed,upgrade,direct,advisory,cve,command,prompt})=>({id,project,manifest,package:pkg,installed,fixed,upgrade,direct,advisory,cve,command,prompt}))},null,2));toast('Patch plan exported')}for(const id of ['search','severity','project','actionability'])el(id).addEventListener(id==='search'?'input':'change',()=>{page=1;render()});el('previous').onclick=()=>{page-=1;render();document.getElementById('findingsSection').scrollIntoView()};el('next').onclick=()=>{page+=1;render();document.getElementById('findingsSection').scrollIntoView()};el('openQueue').onclick=()=>{renderQueue();el('queueDialog').showModal()};el('closeQueue').onclick=()=>el('queueDialog').close();el('clearQueue').onclick=()=>{queue.clear();persist();renderQueue();render()};el('copyQueue').onclick=async()=>{await navigator.clipboard.writeText(queuedFindings().map(f=>f.command||f.prompt).join('\n\n'));toast('Queue copied')};el('exportQueue').onclick=exportPlan;el('exportTop').onclick=()=>download('dependency-audit-report-'+report.meta.reportId+'.json',JSON.stringify(report,null,2));persist();render();
</script>
</body>
</html>`;

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, html, "utf8");
console.log(JSON.stringify({ output: outputPath, ...report.meta, ...report.summary, watchlist: report.watchlist }, null, 2));

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}
