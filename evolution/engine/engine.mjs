// agent-honeypot Phase 3 — System II Engine (orchestrator)
// Escape → antigen → candidates → validator → promoter → lineage
// Lab tier: deterministic, no LLM cost, fully auditable. Production: swap candidate generator via env.

import { extractAntigen, isEscapedSession } from './antigen.mjs';
import { generateCandidates } from './candidate.mjs';
import { filterCandidates } from './validator.mjs';
import { promoteToShadow } from './promoter.mjs';

export async function evolveSession(events, opts = {}) {
  if (!isEscapedSession(events)) return { action: 'no_evolve', reason: 'session not escaped (took bait or priv >=2)' };
  const antigen = extractAntigen(events, { benignBaseline: opts.benignBaseline });
  const candidates = generateCandidates(antigen, { n: opts.n ?? 3 });
  const passing = filterCandidates(candidates, { antigen });
  if (passing.length === 0) return { action: 'no_candidate_passed', antigen, candidates, passing: [] };
  const promoted = passing.map(c => promoteToShadow(c));
  return { action: 'promoted_to_shadow', antigen, candidates, passing, promoted, shadow_count: promoted.length };
}

// Batch helper for offline replay (e.g., nightly job over sessions.jsonl)
export async function evolveBatch(sessionsById, opts = {}) {
  const results = [];
  for (const [sid, events] of Object.entries(sessionsById)) {
    const r = await evolveSession(events, opts);
    results.push({ session_id: sid, ...r });
  }
  return results;
}
