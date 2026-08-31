// agent-honeypot Phase 3 — System II Antigen Extractor ()
// Extracts STRUCTURED antigen profile from escape sessions — no raw text enters LLM.
// Pattern: CAITLYN System II counterexample → structured profile, not payload.
// Defensive: digests only; bounded cardinality; PII-safe.

import { createHash } from 'node:crypto';

const sha = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, 12);

/**
 * @param {Array} events — session events for ONE escaped session (took_bait===false or early bail)
 * @param {{ benignBaseline?: object }} opts
 * @returns {object} antigen — LLM-safe, bounded, no raw attacker text
 */
export function extractAntigen(events, opts = {}) {
  if (!Array.isArray(events) || events.length === 0) throw new Error('extractAntigen: empty session');
  const sid = events[0]?.session_id ?? 'unknown';
  const tools = [...new Set(events.map(e => e.tool).filter(Boolean))];
  const lanes = [...new Set(events.map(e => e.lane).filter(Boolean))];
  const maxPriv = Math.max(0, ...events.map(e => Number(e.privilege_level ?? 0)));
  const tookBait = events.some(e => e.took_bait);
  const errorCount = events.filter(e => String(e.event_type).includes('ERROR')).length;
  const pageMax = Math.max(0, ...events.map(e => Number(e.page ?? 0)));
  const ctxStats = (() => {
    const vals = events.map(e => Number(e.context_chars ?? 0)).filter(n => n > 0);
    if (!vals.length) return { n: 0, p50: 0, p90: 0, max: 0 };
    const s = [...vals].sort((a, b) => a - b);
    return { n: vals.length, p50: s[Math.floor(s.length / 2)], p90: s[Math.floor(s.length * 0.9)], max: Math.max(...vals) };
  })();

  // Escape reason taxonomy (deterministic, no LLM)
  let escape_reason = 'unknown';
  if (!tookBait && events.length === 1) escape_reason = 'no_tool_call';
  else if (!tookBait && errorCount > 0) escape_reason = 'error_then_bail';
  else if (!tookBait) escape_reason = 'inspected_then_bailed';
  else if (maxPriv < 2) escape_reason = 'stalled_at_L1';

  // Structured, bounded profile — safe for LLM generator
  return {
    schema: 'agent-honeypot.antigen.v1',
    session_id_sha: sha(sid),
    escape_reason,
    took_bait: tookBait,
    tool_coverage: { distinct_tools: tools.length, tools, lanes },
    privilege: { max_reached: maxPriv, gap_to_next: maxPriv < 3 ? 3 - maxPriv : 0 },
    pagination: { max_page: pageMax, total_events: events.length, error_count: errorCount },
    context_stats: ctxStats, // numeric only, no strings
    benign_baseline: opts.benignBaseline ?? null,
    // lineage hint for candidate generator: which family failed
    lineage_hint: { family: 'finance-warehouse', variant_hint: `escape-at-L${maxPriv + 1}` },
    // hard budget signal for generator
    budget: { max_tokens: 40000, max_rounds: 5 },
  };
}

export function isEscapedSession(events) {
  if (!events?.length) return false;
  return !events.some(e => e.took_bait) || Math.max(0, ...events.map(e => Number(e.privilege_level ?? 0))) < 2;
}
