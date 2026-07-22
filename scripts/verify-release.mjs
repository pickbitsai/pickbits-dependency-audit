import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { openState, recordAudit } from "./lib/state.mjs";

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (!argv[index].startsWith("--")) continue;
    values[argv[index].slice(2)] = argv[index + 1];
    index += 1;
  }
  return values;
}

const args = parseArgs(process.argv.slice(2));
for (const required of ["file", "repository", "tag", "asset", "db"]) {
  if (!args[required]) {
    console.error(`Missing --${required}`);
    process.exit(2);
  }
}

const filePath = path.resolve(args.file);
const bytes = fs.readFileSync(filePath);
const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
const apiUrl = `https://api.github.com/repos/${args.repository}/releases/tags/${encodeURIComponent(args.tag)}`;
  const response = await fetch(apiUrl, { headers: { accept: "application/vnd.github+json", "user-agent": "PickBits-Dependency-Audit/0.5" } });
if (!response.ok) throw new Error(`Release metadata request failed: ${response.status}`);
const release = await response.json();
const asset = (release.assets || []).find((item) => item.name === args.asset);
if (!asset) throw new Error(`Release asset not found: ${args.asset}`);
const expectedSha256 = String(asset.digest || "").replace(/^sha256:/i, "").toLowerCase() || null;
const digestMatch = Boolean(expectedSha256 && expectedSha256 === sha256);
const slsaAvailable = (release.assets || []).some((item) => /(?:intoto|provenance)/i.test(item.name));
const status = digestMatch ? "DIGEST_VERIFIED" : "BLOCKED_DIGEST_MISMATCH";
const createdAt = new Date().toISOString();
const { db, path: databasePath } = openState(args.db);
db.prepare(`INSERT INTO tool_verifications
  (created_at, file_path, repository, tag, asset_name, sha256, expected_sha256, digest_match, slsa_available, slsa_verified, status)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`)
  .run(createdAt, filePath, args.repository, args.tag, args.asset, sha256, expectedSha256, digestMatch ? 1 : 0, slsaAvailable ? 1 : 0, status);
recordAudit(db, "tool_verification", digestMatch ? "INFO" : "CRITICAL", args.asset, { repository: args.repository, tag: args.tag, sha256, expectedSha256, slsaAvailable, slsaVerified: false, status });
db.close();

const result = {
  schemaVersion: 1,
  createdAt,
  database: databasePath,
  file: filePath,
  repository: args.repository,
  tag: args.tag,
  asset: args.asset,
  sha256,
  expectedSha256,
  digestMatch,
  slsaAvailable,
  slsaVerified: false,
  authenticodeVerified: false,
  status,
  interpretation: digestMatch
    ? "The local bytes match the official release asset. SLSA provenance remains a separate verification gate."
    : "The local bytes do not match the official release asset and must not execute."
};
console.log(JSON.stringify(result, null, 2));
if (!digestMatch) process.exitCode = 1;
