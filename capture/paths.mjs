// Shared filesystem paths. Single source of truth for all components.
// Data lives under <repo>/data/ — never inside src or dist trees.

import { mkdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Walk up from this module to the repo root (the nearest ancestor containing
// package.json). This keeps a single data dir whether the module executes
// from source (capture/paths.mjs) or from the compiled tree (dist/capture/
// paths.mjs) — previously the compiled copy resolved ROOT to dist/ and
// fragmented captures into dist/data/, invisible to the analysis pipeline.
const here = dirname(fileURLToPath(import.meta.url));
function findRoot() {
  let dir = here;
  for (let i = 0; i < 10; i++) {
    if (existsSync(resolve(dir, 'package.json'))) return dir;
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(here, '..'); // fallback: pre-v0.2.1 behavior
}
export const ROOT = findRoot();

// Override for deployments (e.g. container volume, tests).
export const DATA_DIR = process.env.AGENT_HONEYPOT_DATA_DIR
  ? resolve(process.env.AGENT_HONEYPOT_DATA_DIR)
  : resolve(ROOT, 'data');

export const PATHS = {
  root: ROOT,
  dataDir: DATA_DIR,
  sessions: resolve(DATA_DIR, 'sessions.jsonl'),
  bus: resolve(DATA_DIR, 'bus.jsonl'),
  bandit: resolve(DATA_DIR, 'bandit_state.json'),
  tenants: resolve(DATA_DIR, 'tenants.json'),
  lineage: resolve(DATA_DIR, 'lineage.json'),
  usage: resolve(DATA_DIR, 'usage.json'),
  ledger: resolve(DATA_DIR, 'audit_ledger.jsonl'),
  misp: resolve(DATA_DIR, 'misp_out.jsonl'),
  siem: resolve(DATA_DIR, 'siem_deliveries.jsonl'),
  reportOut: resolve(DATA_DIR, 'report'),
};

export function ensureDataDir() {
  mkdirSync(DATA_DIR, { recursive: true });
  return DATA_DIR;
}

export function ensureAllDirs() {
  mkdirSync(PATHS.reportOut, { recursive: true });
  return ensureDataDir();
}
