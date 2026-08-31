// agent-honeypot Phase 3 — Promoter + Lineage (shadow → live)
// Manages shadow deployment lifecycle, lineage.yaml updates, and rollback triggers.
// Defensive: shadow requires min_days + min_sessions + all gates; human approval gate is explicit.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const LINEAGE = resolve(here, '../lineage/lineage.yaml');

function loadLineage() {
  if (!existsSync(LINEAGE)) return { lineage: [], gates: {} };
  const raw = readFileSync(LINEAGE, 'utf8');
  // lineage.yaml is simple — keep as raw text + JSON fallback, no yaml dep required
  try { return JSON.parse(raw); } catch { return { lineage: [], gates: {}, _raw: raw.slice(0, 500) }; }
}
function saveLineage(doc) {
  // Preserve YAML file shape by appending JSON entry as comment-safe — lab tier writes JSON sidecar
  const sidecar = resolve(here, '../lineage/lineage.json');
  writeFileSync(sidecar, JSON.stringify(doc, null, 2));
}

export function promoteToShadow(candidate, { lineageDoc } = {}) {
  const doc = lineageDoc ?? loadLineage();
  const entry = {
    id: candidate.id,
    family: candidate.lineage?.parent_family ?? 'finance-warehouse',
    variant: candidate.lineage?.parent_variant ?? 'candidate',
    status: 'shadow',
    parent: candidate.lineage?.parent_variant ?? null,
    created_at: candidate.created_at ?? new Date().toISOString(),
    shadow_since: new Date().toISOString(),
    strategy: candidate.strategy,
    delta: candidate.delta,
    budgets: { max_rounds: 5, max_tokens_per_run: 40000, false_positive_percent: 2.0, daily_tokens: 200000 },
    shadow_rules: { min_days: 7, min_sessions: 50, auto_promote: false },
  };
  doc.lineage = [...(doc.lineage ?? []), entry];
  saveLineage(doc);
  return entry;
}

export function canPromoteToLive(lineageId, { sessionsInShadow = 0, daysInShadow = 0, gatesPass = false } = {}) {
  const reasons = [];
  if (sessionsInShadow < 50) reasons.push(`sessions ${sessionsInShadow}/50`);
  if (daysInShadow < 7) reasons.push(`days ${daysInShadow}/7`);
  if (!gatesPass) reasons.push('gates not all pass (tier0 + benign + anti_fingerprint)');
  // human approval is always required per lineage.yaml gates.promote
  reasons.push('human_approval_required');
  if (reasons.length > 1) return { can: false, reasons }; // >1 because human_approval is always present
  // In lab, with mocked gatesPass, this still requires human — return blocked with single reason
  return { can: false, reasons, note: 'lab: human gate blocks auto-promote by design' };
}

export function rollbackIfNeeded({ captureRateDropPct = 0, benignFpPct = 0 }) {
  const triggers = [];
  if (captureRateDropPct > 20) triggers.push(`capture_rate_drop ${captureRateDropPct}% > 20%`);
  if (benignFpPct > 2) triggers.push(`benign_fp ${benignFpPct}% > 2%`);
  return { should_rollback: triggers.length > 0, triggers };
}
