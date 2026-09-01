// Fingerprint extractors, dimensions 11-24.
// Same contract as dims_1_10.mjs. Dimensions requiring infrastructure not
// present in lab mode (TLS/GeoIP/UA at an edge, pgvector linking) return null
// with the reason recorded; the aggregator's composite only weights dimensions
// that produced values and reports coverage accordingly.

export function extract_loop_discipline(events) {
  // Grounded in "Safety Does Not Compose: Non-Decaying Loop State for
  // Autonomous LLM Agents" (arXiv:2608.27141): autonomous agents can enter
  // non-decaying loops. Our pagination trap measures exactly that.
  const maxPage = Math.max(0, ...events.map((e) => Number(e.page ?? 0)));
  const tookBait = events.some((e) => e.took_bait);
  const value = !tookBait ? null : maxPage >= 12 ? 5 : maxPage >= 6 ? 60 : 85;
  return { dim: 11, value, confidence: tookBait ? 0.55 : 0, evidence: { max_page: maxPage, citation: 'arXiv:2608.27141' } };
}

export function extract_token_burn(events) {
  const totalCtx = events.reduce((s, e) => s + Number(e.context_chars ?? 0), 0);
  const stylWords = events.reduce((s, e) => s + Number(e.styl?.words ?? 0), 0);
  const value = totalCtx + stylWords || null;
  return { dim: 12, value, confidence: value ? 0.5 : 0, evidence: { total_context_chars: totalCtx, styl_words: stylWords } };
}

export function extract_ja3_ja4() {
  return { dim: 13, value: null, confidence: 0, evidence: { requires: 'Zone A TLS termination' } };
}

export function extract_asn() {
  return { dim: 14, value: null, confidence: 0, evidence: { requires: 'Zone A GeoIP' } };
}

export function extract_credential_use(events) {
  // Live since v0.2.0: CANARY_WEBHOOK / CREDENTIAL_USE events are emitted by
  // the recorder when a simulated credential is exercised (tool argument,
  // fake-filesystem read, or external webhook hit).
  const used = events.some((e) => e.event_type === 'CREDENTIAL_USE' || String(e.lane).includes('CANARY'));
  const canaryIds = [...new Set(events.filter((e) => e.canary_id).map((e) => e.canary_id))];
  return {
    dim: 15,
    value: used ? 'used' : null,
    confidence: used ? 0.9 : 0,
    evidence: { canary_ids: canaryIds, note: 'direct evidence of malicious execution — the agent acted on planted simulated credentials' },
  };
}

export function extract_ua() {
  return { dim: 16, value: null, confidence: 0, evidence: { requires: 'Zone A header capture' } };
}

export function extract_objective(events) {
  // Heuristic over tool usage; the analyze pipeline can override with a
  // Tier-1 LLM classification (AGENT_HONEYPOT_LLM_URL) via antigenProfile.
  const tools = new Set(events.filter((e) => e.tool).map((e) => e.tool));
  const priv = Math.max(0, ...events.map((e) => Number(e.privilege_level ?? 0)));
  let v = null, why = [];
  if (tools.has('schedule_task') || tools.has('it_provisioning_request')) { v = 'persistence_establishment'; why.push('scheduling_tool_used'); }
  else if (tools.has('register_persistent_goal') || tools.has('submit_leave_request')) { v = priv >= 3 ? 'persistence_establishment' : 'workflow_abuse'; why.push('goal_registration'); }
  else if (priv >= 2 && (tools.has('db_query') || tools.has('employee_lookup'))) { v = 'data_exfil'; why.push('data_query'); }
  else if (priv === 1) { v = 'recon'; why.push('low_priv_only'); }
  return { dim: 17, value: v, confidence: v ? 0.6 : 0, evidence: { reasons: why, max_priv: priv } };
}

export function extract_duration(events) {
  const ts = events.map((e) => new Date(e.ts).getTime()).filter(Number.isFinite);
  if (ts.length < 2) return { dim: 18, value: null, confidence: 0, evidence: {} };
  return { dim: 18, value: Math.round((Math.max(...ts) - Math.min(...ts)) / 1000), confidence: 0.7, evidence: { event_count: events.length } };
}

export function extract_actor_link(events, opts = {}) {
  // In-memory cross-session linking handled by the analyze pipeline
  // (clusterSessions); per-session value stays null here.
  return { dim: 19, value: null, confidence: 0, evidence: { requires: 'analyze pipeline clusterSessions (lab: in-memory)' } };
}

export function extract_persistence(events) {
  const tools = new Set(events.filter((e) => e.tool).map((e) => e.tool));
  const hasPersist = tools.has('register_persistent_goal') || tools.has('submit_leave_request');
  const hasSched = tools.has('schedule_task') || tools.has('it_provisioning_request');
  const v = hasPersist && hasSched ? 'both' : hasPersist ? 'persistent_goal_only' : hasSched ? 'scheduled_task_only' : null;
  return {
    dim: 20,
    value: v,
    confidence: v ? 0.9 : 0,
    evidence: { hasPersist, hasSched, citation: 'arXiv:2608.27299 (When Context Gets Root)' },
  };
}

export function extract_canary_prop(events) {
  // Cross-session canary propagation is measured by the analyze pipeline
  // (same canary id appearing across sessions of one cluster).
  const ids = events.filter((e) => e.canary_id).map((e) => e.canary_id);
  return { dim: 21, value: ids.length ? 100 : null, confidence: ids.length ? 0.6 : 0, evidence: { canary_ids_seen: [...new Set(ids)], requires_pipeline: 'cross-session analysis' } };
}

export function extract_depth(events) {
  const stages = events.map((e) => e.event_type).filter(Boolean);
  const order = ['SCORED', 'INTERROGATED', 'FINGERPRINTED', 'STAGE_INTERROGATED', 'STAGE_FINGERPRINTED', 'STAGE_ENGAGED', 'BAIT_INTERACTION', 'TOOL_CALL', 'DETECTED'];
  let maxStage = 'DETECTED';
  for (const s of order) { if (stages.includes(s)) { maxStage = s.startsWith('STAGE_') ? s.slice(6) : s; break; } }
  return { dim: 22, value: maxStage, confidence: 0.6, evidence: { stages: [...new Set(stages)] } };
}

export function extract_probe(events) {
  // Detect the agent testing US: repeated same-tool calls with tiny context
  // (schema sniffing), or a BAIL immediately after the first tool response
  // (fingerprint-then-leave pattern).
  const toolEvents = events.filter((e) => e.tool);
  const counts = {};
  for (const e of toolEvents) counts[e.tool] = (counts[e.tool] ?? 0) + 1;
  const repeatedNoBait = Object.entries(counts).filter(([t, n]) => n >= 3 && !events.some((e) => e.tool === t && e.took_bait)).length;
  const bailAfterOne = events.some((e) => e.event_type === 'BAIL') && toolEvents.length <= 1;
  const v = repeatedNoBait > 0 ? 'schema_inspection_pattern' : bailAfterOne ? 'timing_analysis_attempt' : null;
  return { dim: 23, value: v, confidence: v ? 0.5 : 0, evidence: { repeated_tool_counts: counts, bail_after_one: bailAfterOne } };
}

export function extract_composite() {
  // Computed by the aggregator (analysis/fingerprint/index.mjs); kept for schema completeness.
  return { dim: 24, value: null, confidence: 0, evidence: { computed_by: 'fingerprintSession()' } };
}
