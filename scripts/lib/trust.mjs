import path from "node:path";

const SAFE_NPM_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/i;
const SAFE_VERSION = /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$/;
const SAFE_ADVISORY = /^(?:CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z-]+|[A-Z][A-Z0-9_.-]{1,63})$/i;

export function detectPromptInjection(value, patterns = []) {
  const raw = String(value || "");
  let decoded = raw;
  try { decoded = decodeURIComponent(raw.replaceAll("+", " ")); } catch {}
  const text = `${raw}\n${decoded}`.toLowerCase();
  const matches = patterns.filter((pattern) => text.includes(String(pattern).toLowerCase()));
  return [...new Set(matches)];
}

export function safePackageName(value, ecosystem = "npm") {
  const text = String(value || "").trim();
  if (ecosystem.toLowerCase() === "npm") return SAFE_NPM_NAME.test(text);
  return /^[A-Za-z0-9][A-Za-z0-9@/+_.:-]{0,255}$/.test(text);
}

export function safeVersion(value) {
  return SAFE_VERSION.test(String(value || "").trim());
}

export function safeAdvisory(value) {
  return SAFE_ADVISORY.test(String(value || "").trim());
}

export function packageNameFromLockPath(lockPath) {
  const normalized = String(lockPath || "").replaceAll("\\", "/");
  const marker = "/node_modules/";
  const index = normalized.lastIndexOf(marker);
  const tail = index >= 0 ? normalized.slice(index + marker.length) : normalized.replace(/^node_modules\//, "");
  const parts = tail.split("/").filter(Boolean);
  if (!parts.length) return null;
  return parts[0].startsWith("@") && parts[1] ? `${parts[0]}/${parts[1]}` : parts[0];
}

export function sourceHost(resolved) {
  try {
    const parsed = new URL(String(resolved));
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function assessNpmLockRecord({ name, record, vulnerabilities = [], policy }) {
  const reasons = [];
  const injectionSignals = [name, record?.version, record?.resolved]
    .flatMap((value) => detectPromptInjection(value, policy.promptInjectionPatterns));
  const host = sourceHost(record?.resolved);
  let state = "ALLOW_LOCKED";

  if (!safePackageName(name, "npm") || !safeVersion(record?.version)) {
    state = "BLOCK";
    reasons.push("invalid package identity or version grammar");
  }
  if (injectionSignals.length) {
    state = "BLOCK";
    reasons.push(`prompt-injection marker in package-controlled metadata: ${[...new Set(injectionSignals)].join(", ")}`);
  }
  if (policy.blockPlainHttp && /^http:\/\//i.test(record?.resolved || "")) {
    state = "BLOCK";
    reasons.push("artifact uses unencrypted HTTP");
  }
  if (record?.resolved && host && !policy.approvedRegistryHosts.includes(host) && state !== "BLOCK") {
    state = "QUARANTINE";
    reasons.push(`unapproved registry host: ${host}`);
  }
  if (policy.quarantineInstallScripts && record?.hasInstallScript && state !== "BLOCK") {
    state = "QUARANTINE";
    reasons.push("package declares an install lifecycle script");
  }
  if (policy.requireLockfileIntegrity && !record?.integrity && !String(record?.resolved || "").startsWith("file:") && !["BLOCK", "QUARANTINE"].includes(state)) {
    state = "REVIEW";
    reasons.push("lockfile has no integrity digest");
  }
  const reviewFindings = vulnerabilities.filter((item) => policy.reviewSeverities.includes(item.severity));
  if (reviewFindings.length && state === "ALLOW_LOCKED") {
    state = "REVIEW";
    reasons.push(`${reviewFindings.length} high-priority known vulnerability finding(s)`);
  }
  if (!reasons.length) reasons.push("exact version and integrity are locked to an approved registry");
  reasons.push("publisher provenance not established by the lockfile");

  return {
    state,
    reasons,
    registryHost: host,
    integrityPresent: Boolean(record?.integrity),
    installScript: Boolean(record?.hasInstallScript),
    provenance: "UNKNOWN",
    injectionSignals: [...new Set(injectionSignals)],
  };
}

export function canonicalRemediationRequest(finding) {
  const ecosystem = String(finding.ecosystem || "unknown").toLowerCase();
  const advisory = finding.cve || finding.advisory;
  const valid = safePackageName(finding.package, ecosystem) &&
    safeVersion(finding.installed) &&
    (!finding.fixed || safeVersion(finding.fixed)) &&
    safeAdvisory(advisory);
  if (!valid) {
    return {
      schemaVersion: 1,
      operation: "manual_review",
      findingId: finding.id,
      reason: "Package-controlled fields failed the remediation schema allowlist"
    };
  }
  const manifest = String(finding.manifest || "").replaceAll("\\", "/");
  const safeManifest = !manifest.includes("..") && !/[\u0000-\u001f]/.test(manifest) ? manifest : null;
  const request = {
    schemaVersion: 1,
    operation: finding.acve ? "investigate_dependency" : (finding.fixed ? "update_dependency" : "investigate_dependency"),
    findingId: finding.id,
    ecosystem,
    package: finding.package,
    installed: finding.installed,
    fixed: finding.fixed || null,
    advisory,
    manifest: safeManifest,
    approval: "required",
  };
  if (finding.note) request.note = String(finding.note).replace(/\s+/g, " ").slice(0, 500);
  return request;
}

export function relativeProject(target, source) {
  const normalizedTarget = path.win32.normalize(target);
  const normalizedSource = path.win32.normalize(source);
  const relative = path.win32.relative(normalizedTarget, normalizedSource);
  if (!relative || relative.startsWith("..")) return "(external)";
  const segments = relative.split(/[\\/]/);
  // A single-segment relative path is the lockfile itself at the target root
  // (single-project scan) — the first segment would be "package-lock.json",
  // not a project name. Attribute it to the target's own folder instead.
  if (segments.length === 1) return path.win32.basename(normalizedTarget) || "(root)";
  return segments[0];
}
