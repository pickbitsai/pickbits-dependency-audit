import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { openState, recordAudit } from "./lib/state.mjs";
import { assessNpmLockRecord, detectPromptInjection, packageNameFromLockPath, relativeProject } from "./lib/trust.mjs";

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) continue;
    const key = item.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) values[key] = "true";
    else {
      values[key] = next;
      index += 1;
    }
  }
  return values;
}

function severityLabel(vulnerability) {
  const raw = String(vulnerability?.database_specific?.severity || "UNKNOWN").toUpperCase();
  if (raw === "MEDIUM") return "MODERATE";
  return ["CRITICAL", "HIGH", "MODERATE", "LOW"].includes(raw) ? raw : "UNKNOWN";
}

function cveFor(vulnerability) {
  if (/^CVE-/.test(vulnerability?.id || "")) return vulnerability.id;
  return (vulnerability?.aliases || []).find((alias) => /^CVE-/.test(alias)) || null;
}

function sourcePath(result) {
  return String(result?.source?.path || result?.source || "unknown");
}

function relativeSource(target, source) {
  const relative = path.win32.relative(path.win32.normalize(target), path.win32.normalize(source));
  return relative && !relative.startsWith("..") ? relative : source;
}

function hash(parts) {
  return crypto.createHash("sha256").update(parts.join("\u0000")).digest("hex");
}

function inventoryFromScan(scan, target, policy) {
  const detections = [];
  const coordinates = new Map();
  const sourceFiles = new Set();
  let packageOccurrences = 0;
  const injectionEvents = [];
  for (const result of scan.results || []) {
    const source = sourcePath(result);
    sourceFiles.add(relativeSource(target, source));
    for (const group of result.packages || []) {
      const pkg = group.package || {};
      if (!pkg.name || !pkg.version) continue;
      packageOccurrences += 1;
      const coordinate = `${String(pkg.ecosystem || "unknown").toLowerCase()}\u0000${String(pkg.name).toLowerCase()}\u0000${pkg.version}`;
      const vulnerabilities = [];
      for (const vulnerability of group.vulnerabilities || []) {
        const severity = severityLabel(vulnerability);
        const cve = cveFor(vulnerability);
        const advisory = String(vulnerability.id || cve || "UNKNOWN");
        const injectionSignals = [pkg.name, pkg.version, source, advisory, vulnerability.summary, vulnerability.details]
          .flatMap((value) => detectPromptInjection(value, policy.promptInjectionPatterns));
        const detection = {
          detectionKey: hash([target, source, pkg.ecosystem, pkg.name, pkg.version, advisory]),
          target,
          project: relativeProject(target, source),
          source: relativeSource(target, source),
          ecosystem: String(pkg.ecosystem || "unknown"),
          package: String(pkg.name),
          version: String(pkg.version),
          advisory,
          cve,
          severity,
        };
        detections.push(detection);
        vulnerabilities.push({ advisory, cve, severity });
        if (injectionSignals.length) injectionEvents.push({ detectionKey: detection.detectionKey, advisory, signals: [...new Set(injectionSignals)] });
      }
      coordinates.set(coordinate, [...(coordinates.get(coordinate) || []), ...vulnerabilities]);
    }
  }
  return { detections, coordinates, sourceFiles, packageOccurrences, injectionEvents };
}

function findPackageLocks(root) {
  const found = [];
  const skipped = new Set([".git", ".claude", ".next", ".turbo", "node_modules", "dist", "build", "coverage", "reports"]);
  const stack = [root];
  while (stack.length) {
    const directory = stack.pop();
    let entries;
    try { entries = fs.readdirSync(directory, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!skipped.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && entry.name === "package-lock.json") found.push(fullPath);
    }
  }
  return found.sort((a, b) => a.localeCompare(b));
}

function assessLockfiles(target, coordinates, policy) {
  const assessments = [];
  const parseFailures = [];
  for (const lockPath of findPackageLocks(target)) {
    let lock;
    try { lock = JSON.parse(fs.readFileSync(lockPath, "utf8")); }
    catch (error) {
      parseFailures.push({ source: relativeSource(target, lockPath), error: error.message });
      continue;
    }
    for (const [packagePath, record] of Object.entries(lock.packages || {})) {
      if (!packagePath || !record?.version) continue;
      const name = packageNameFromLockPath(packagePath);
      if (!name) continue;
      const coordinateKey = `npm\u0000${name.toLowerCase()}\u0000${record.version}`;
      const assessment = assessNpmLockRecord({ name, record, vulnerabilities: coordinates.get(coordinateKey) || [], policy });
      assessments.push({
        coordinate: `pkg:npm/${name}@${record.version}`,
        source: relativeSource(target, lockPath),
        ...assessment,
      });
    }
  }
  return { assessments, parseFailures };
}

function countBy(items, selector) {
  const counts = {};
  for (const item of items) {
    const key = selector(item);
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

const args = parseArgs(process.argv.slice(2));
for (const required of ["scan", "target", "db", "output"]) {
  if (!args[required]) {
    console.error(`Missing --${required}`);
    process.exit(2);
  }
}

const scanPath = path.resolve(args.scan);
const target = path.resolve(args.target);
const outputPath = path.resolve(args.output);
const policyPath = path.resolve(args.policy || "dependency-audit-policy.json");
const complete = args.complete !== "false";
const scan = JSON.parse(fs.readFileSync(scanPath, "utf8"));
const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
const inventory = inventoryFromScan(scan, target, policy);
const lockAudit = assessLockfiles(target, inventory.coordinates, policy);
const now = new Date().toISOString();
const runKey = hash([target, now, fs.statSync(scanPath).mtimeMs, crypto.randomUUID()]);
const { db, path: databasePath } = openState(args.db);

db.exec("BEGIN IMMEDIATE");
let runId;
try {
  const inserted = db.prepare(`INSERT INTO scan_runs
    (run_key, target, started_at, completed_at, complete, source_files, package_occurrences, findings, open_findings, pending_findings, closed_findings, trust_json, result_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, '{}', '{}')`)
    .run(runKey, target, now, now, complete ? 1 : 0, inventory.sourceFiles.size, inventory.packageOccurrences, inventory.detections.length);
  runId = Number(inserted.lastInsertRowid);

  const existingRows = db.prepare("SELECT detection_key, status, missing_scans FROM detections WHERE target = ?").all(target);
  const currentKeys = new Set(inventory.detections.map((item) => item.detectionKey));
  const upsert = db.prepare(`INSERT INTO detections
    (detection_key, target, project, source, ecosystem, package, version, advisory, cve, severity, first_seen, last_seen, status, missing_scans)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 0)
    ON CONFLICT(detection_key) DO UPDATE SET project=excluded.project, source=excluded.source, severity=excluded.severity,
      cve=excluded.cve, last_seen=excluded.last_seen, status='open', missing_scans=0`);
  const observe = db.prepare("INSERT INTO observations (run_id, detection_key, observed_at) VALUES (?, ?, ?)");
  for (const item of inventory.detections) {
    upsert.run(item.detectionKey, target, item.project, item.source, item.ecosystem, item.package, item.version, item.advisory, item.cve, item.severity, now, now);
    observe.run(runId, item.detectionKey, now);
  }

  if (complete) {
    const markMissing = db.prepare("UPDATE detections SET missing_scans = ?, status = ? WHERE detection_key = ?");
    for (const existing of existingRows) {
      if (currentKeys.has(existing.detection_key) || existing.status === "closed_fixed") continue;
      const missingScans = Number(existing.missing_scans) + 1;
      const status = missingScans >= Number(policy.closeAfterSuccessfulScans || 2) ? "closed_fixed" : "pending_verification";
      markMissing.run(missingScans, status, existing.detection_key);
    }
  }

  const insertTrust = db.prepare(`INSERT INTO trust_assessments
    (run_id, coordinate, source, state, integrity_present, registry_host, install_script, provenance, reasons_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  for (const item of lockAudit.assessments) {
    insertTrust.run(runId, item.coordinate, item.source, item.state, item.integrityPresent ? 1 : 0, item.registryHost, item.installScript ? 1 : 0, item.provenance, JSON.stringify(item.reasons));
  }

  for (const event of inventory.injectionEvents) recordAudit(db, "prompt_injection_signal", "HIGH", event.advisory, event);
  for (const failure of lockAudit.parseFailures) recordAudit(db, "lockfile_parse_failure", "MEDIUM", failure.source, failure);

  const statusCounts = Object.fromEntries(db.prepare("SELECT status, COUNT(*) AS count FROM detections WHERE target = ? GROUP BY status").all(target).map((row) => [row.status, Number(row.count)]));
  const trustCounts = countBy(lockAudit.assessments, (item) => item.state);
  const result = {
    schemaVersion: 1,
    runId,
    runKey,
    target,
    generatedAt: now,
    complete,
    database: databasePath,
    scan: {
      sourceFiles: inventory.sourceFiles.size,
      packageOccurrences: inventory.packageOccurrences,
      findings: inventory.detections.length,
      detectionStates: statusCounts,
    },
    trust: {
      npmLockfiles: findPackageLocks(target).length,
      packageAssessments: lockAudit.assessments.length,
      states: trustCounts,
      parseFailures: lockAudit.parseFailures,
      publisherProvenanceVerified: 0,
    },
    promptInjection: {
      signals: inventory.injectionEvents.length,
      interpretation: "Heuristic signals are quarantined evidence, not proof of malicious intent."
    }
  };
  db.prepare("UPDATE scan_runs SET open_findings=?, pending_findings=?, closed_findings=?, trust_json=?, result_json=? WHERE id=?")
    .run(statusCounts.open || 0, statusCounts.pending_verification || 0, statusCounts.closed_fixed || 0, JSON.stringify(trustCounts), JSON.stringify(result), runId);
  recordAudit(db, "scan_imported", inventory.injectionEvents.length ? "HIGH" : "INFO", target, { runId, findings: inventory.detections.length, complete });
  db.exec("COMMIT");
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  db.exec("ROLLBACK");
  throw error;
} finally {
  db.close();
}
