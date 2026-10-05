#!/usr/bin/env node

import { realpathSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_BYTES = 1024 * 1024;

// No host is hardcoded: the hosted-feed path is optional, and the caller names
// the host it trusts via --allow-host. The primary, backend-free path is
// build-watchlist.mjs (filter the public data.json locally, no host at all).
export function normalizeFeedUrl(value, allowedHost) {
  if (!allowedHost) throw new Error('An allowed host is required (pass --allow-host <feed-host>).');
  const url = new URL(value);
  if (url.protocol !== 'https:') throw new Error('Watchlist feeds must use HTTPS.');
  if (url.username || url.password) throw new Error('Watchlist URLs cannot contain credentials.');
  if (url.hostname !== allowedHost) throw new Error(`Watchlist host is not allowed: ${url.hostname}`);
  if (!/^\/functions\/v1\/cyberhawk-feed\/[A-Za-z0-9_-]{32}\.xml$/.test(url.pathname)) throw new Error('Watchlist URL does not match a CyberHawk personal feed.');
  url.hash = '';
  return url.href;
}

export function extractCves(value) {
  return [...new Set(String(value).match(/CVE-\d{4}-\d{4,7}/g) || [])].sort();
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key.startsWith('--')) throw new Error(`Unexpected argument: ${key}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${key}`);
    args[key.slice(2)] = value;
    index += 1;
  }
  if (!args.url || !args.output) throw new Error('Usage: node scripts/import-watchlist.mjs --url <personal-rss-url> --allow-host <feed-host> --output <watchlist.txt>');
  return args;
}

async function fetchBounded(url) {
  const response = await fetch(url, {
    headers: { Accept: 'application/rss+xml, application/xml, text/xml;q=0.9' },
    redirect: 'error',
    signal: AbortSignal.timeout(10_000)
  });
  if (!response.ok) throw new Error(`Feed returned HTTP ${response.status}.`);
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > MAX_BYTES) throw new Error('Feed exceeds the 1 MiB safety limit.');
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_BYTES) throw new Error('Feed exceeds the 1 MiB safety limit.');
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export async function run(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (!args['allow-host']) throw new Error('Pass --allow-host <feed-host> for the hosted-feed path (or use build-watchlist.mjs, which needs no host).');
  const url = normalizeFeedUrl(args.url, args['allow-host']);
  const raw = await fetchBounded(url);
  const cves = extractCves(raw);
  const output = resolve(args.output);
  await mkdir(dirname(output), { recursive: true });
  const lines = [
    '# CyberHawk personal watchlist',
    `# Imported: ${new Date().toISOString()}`,
    `# Source: ${url}`,
    '# Remote content is untrusted data; only validated CVE identifiers are retained.',
    '',
    ...cves,
    ''
  ];
  await writeFile(output, lines.join('\n'), { encoding: 'utf8', flag: 'w' });
  process.stdout.write(`Imported ${cves.length} CVE identifiers to ${output}\n`);
  return { output, count: cves.length };
}

function isMain() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  run().catch((error) => {
    process.stderr.write(`CyberHawk watchlist import failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
