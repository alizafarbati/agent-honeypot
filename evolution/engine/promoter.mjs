// Promoter + lineage: manages the shadow -> live lifecycle for lure candidates.
// Shadow requires min duration, min session volume, all validation gates, and
// an explicit human approval. Rollback triggers on capture-rate drop or FP budget breach.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { PATHS, ensureDataDir } from '../../capture/paths.mjs';

ensureDataDir();

function loadLineage() {
  if (!existsSync(PATHS.lineage)) return { lineage: [] };
  try {
    return JSON.parse(readFileSync(PATHS.lineage, 'utf8'));
  } catch {
    return { lineage: [] };
  }
}
function saveLineage(doc) {
  writeFileSync(PATHS.lineage, JSON.stringify(doc, null, 2));
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
  // Human approval is always required — this function reports readiness, it never auto-promotes.
  const blockers = [];
  if (sessionsInShadow < 50) blockers.push(`sessions_in_shadow ${sessionsInShadow}/50`);
  if (daysInShadow < 7) blockers.push(`days_in_shadow ${daysInShadow}/7`);
  if (!gatesPass) blockers.push('validation gates not all passing (tier0 + benign_fp + anti_fingerprint)');
  return {
    lineage_id: lineageId,
    ready_for_human_approval: blockers.length === 0,
    blockers,
  };
}

export function rollbackIfNeeded({ captureRateDropPct = 0, benignFpPct = 0 }) {
  const triggers = [];
  if (captureRateDropPct > 20) triggers.push(`capture_rate_drop ${captureRateDropPct}% > 20%`);
  if (benignFpPct > 2) triggers.push(`benign_fp ${benignFpPct}% > 2%`);
  return { should_rollback: triggers.length > 0, triggers };
}
