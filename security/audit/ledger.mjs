// agent-honeypot Phase 9 — Immutable Audit Ledger (hash chain, )
// Append-only ledger: each entry hashes prev entry. No blockchain — operational simplicity + audit integrity.
// Stored at security/audit/ledger.jsonl (lab). Enterprise: mirrored to WORM R2 with object lock.

import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const LEDGER = resolve(here, 'ledger.jsonl');
mkdirSync(dirname(LEDGER), { recursive: true });

function hash(obj) { return createHash('sha256').update(JSON.stringify(obj)).digest('hex'); }

function lastHash() {
  if (!existsSync(LEDGER)) return '0'.repeat(64);
  const lines = readFileSync(LEDGER, 'utf8').trim().split('\n').filter(Boolean);
  if (!lines.length) return '0'.repeat(64);
  try { return JSON.parse(lines[lines.length - 1]).entry_hash; } catch { return '0'.repeat(64); }
}

export function appendLedger({ actor, action, target, detail = {} }) {
  const prev = lastHash();
  const entry = { ts: new Date().toISOString(), actor, action, target, detail, prev_hash: prev };
  const entry_hash = hash(entry);
  const line = JSON.stringify({ ...entry, entry_hash });
  appendFileSync(LEDGER, line + '\n');
  return { entry_hash, prev_hash: prev };
}

export function verifyLedger() {
  if (!existsSync(LEDGER)) return { ok: true, entries: 0 };
  const lines = readFileSync(LEDGER, 'utf8').trim().split('\n').filter(Boolean);
  let prev = '0'.repeat(64);
  for (let i = 0; i < lines.length; i++) {
    const obj = JSON.parse(lines[i]);
    const { entry_hash, ...rest } = obj;
    const recomputed = hash(rest);
    if (recomputed !== entry_hash) return { ok: false, bad_index: i, expected: recomputed, got: entry_hash };
    if (rest.prev_hash !== prev) return { ok: false, bad_index: i, reason: 'prev_hash mismatch' };
    prev = entry_hash;
  }
  return { ok: true, entries: lines.length, head: prev };
}

export function ledgerPath() { return LEDGER; }
