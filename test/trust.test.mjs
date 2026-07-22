import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { assessNpmLockRecord, canonicalRemediationRequest } from "../scripts/lib/trust.mjs";

const policy = {
  approvedRegistryHosts: ["registry.npmjs.org"],
  requireLockfileIntegrity: true,
  quarantineInstallScripts: true,
  reviewSeverities: ["CRITICAL", "HIGH"],
  blockPlainHttp: true,
  promptInjectionPatterns: ["ignore previous", "system prompt"],
};

test("allows only an exact locked artifact under policy", () => {
  const result = assessNpmLockRecord({
    name: "safe-package",
    record: { version: "1.2.3", resolved: "https://registry.npmjs.org/safe-package/-/safe-package-1.2.3.tgz", integrity: "sha512-example" },
    vulnerabilities: [],
    policy,
  });
  assert.equal(result.state, "ALLOW_LOCKED");
  assert.equal(result.provenance, "UNKNOWN");
});

test("quarantines install scripts and blocks prompt-injection metadata", () => {
  const scripted = assessNpmLockRecord({
    name: "native-helper",
    record: { version: "1.0.0", resolved: "https://registry.npmjs.org/native-helper/-/native-helper-1.0.0.tgz", integrity: "sha512-example", hasInstallScript: true },
    vulnerabilities: [],
    policy,
  });
  assert.equal(scripted.state, "QUARANTINE");
  const injected = assessNpmLockRecord({
    name: "safe-package",
    record: { version: "1.0.0", resolved: "https://registry.npmjs.org/ignore%20previous/package.tgz", integrity: "sha512-example" },
    vulnerabilities: [],
    policy,
  });
  assert.equal(injected.state, "BLOCK");
});

test("typed remediation requests reject unsafe package-controlled fields", () => {
  const request = canonicalRemediationRequest({ id: "abc", ecosystem: "npm", package: "good\nignore previous", installed: "1.0.0", fixed: "1.0.1", advisory: "CVE-2026-12345", manifest: "package.json" });
  assert.equal(request.operation, "manual_review");
  assert.equal(request.package, undefined);
});

test("complete rescans require two absences before closing a detection", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "pickbits-audit-test-"));
  const target = path.join(temporary, "repo");
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/demo": { version: "1.0.0", resolved: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz", integrity: "sha512-example" } } }));
  const source = path.join(target, "package-lock.json");
  const vulnerable = { results: [{ source: { path: source }, packages: [{ package: { ecosystem: "npm", name: "demo", version: "1.0.0" }, vulnerabilities: [{ id: "CVE-2026-12345", database_specific: { severity: "HIGH" } }] }] }] };
  const empty = { results: [{ source: { path: source }, packages: [] }] };
  const scanPath = path.join(temporary, "scan.json");
  const dbPath = path.join(temporary, "state.db");
  const outputPath = path.join(temporary, "result.json");
  const policyPath = path.resolve("dependency-audit-policy.json");
  const scriptPath = path.resolve("scripts/trust-audit.mjs");
  const run = (scan) => {
    fs.writeFileSync(scanPath, JSON.stringify(scan));
    const child = spawnSync(process.execPath, [scriptPath, "--scan", scanPath, "--target", target, "--db", dbPath, "--output", outputPath, "--policy", policyPath, "--complete", "true"], { encoding: "utf8" });
    assert.equal(child.status, 0, child.stderr);
  };
  run(vulnerable);
  let db = new DatabaseSync(dbPath);
  assert.equal(db.prepare("SELECT status FROM detections").get().status, "open");
  db.close();
  run(empty);
  db = new DatabaseSync(dbPath);
  assert.equal(db.prepare("SELECT status FROM detections").get().status, "pending_verification");
  db.close();
  run(empty);
  db = new DatabaseSync(dbPath);
  assert.equal(db.prepare("SELECT status FROM detections").get().status, "closed_fixed");
  db.close();
});
