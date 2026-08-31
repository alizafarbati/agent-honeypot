// agent-honeypot Fingerprint — dims 11-24 stubs (Phase 2 targets)
// Each exported function matches dims_1_10.mjs signature: (events) => {dim, value, confidence, evidence}
// Lab tier returns confidence 0 so aggregator's composite ignores them; Phase 2 replaces with real extractors.

export function extract_loop_discipline(events) {
  const maxPage = Math.max(0, ...events.map(e => Number(e.page ?? 0)));
  const tookBait = events.some(e => e.took_bait);
  // If agent paginated to 12 and still going, loop discipline low (runaway)
  const value = !tookBait ? null : maxPage >= 12 ? 5 : maxPage >= 6 ? 60 : 85;
  return { dim: 11, value, confidence: tookBait ? 0.55 : 0, evidence: { max_page: maxPage } };
}
export function extract_token_burn(events) {
  const totalCtx = events.reduce((s, e) => s + Number(e.context_chars ?? 0), 0);
  return { dim: 12, value: totalCtx || null, confidence: totalCtx ? 0.5 : 0, evidence: { total_context_chars: totalCtx } };
}
export function extract_ja3_ja4() { return { dim: 13, value: null, confidence: 0, evidence: { requires: 'Zone A TLS termination' } }; }
export function extract_asn() { return { dim: 14, value: null, confidence: 0, evidence: { requires: 'Zone A GeoIP' } }; }
export function extract_credential_use(events) {
  const used = events.some(e => String(e.lane).includes('CANARY') || e.tool === 'credential_use');
  return { dim: 15, value: used ? 'used' : null, confidence: used ? 0.9 : 0, evidence: { canary_lane: used } };
}
export function extract_ua() { return { dim: 16, value: null, confidence: 0, evidence: { requires: 'Zone A header capture' } }; }
export function extract_objective(events) {
  const priv = Math.max(0, ...events.map(e => Number(e.privilege_level ?? 0)));
  const v = priv >= 3 ? 'persistence_establishment' : priv === 2 ? 'data_exfil' : priv === 1 ? 'recon' : null;
  return { dim: 17, value: v, confidence: v ? 0.6 : 0, evidence: { max_priv: priv } };
}
export function extract_duration(events) {
  const ts = events.map(e => new Date(e.ts).getTime()).filter(n => Number.isFinite(n));
  if (ts.length < 2) return { dim: 18, value: null, confidence: 0, evidence: {} };
  return { dim: 18, value: Math.round((Math.max(...ts) - Math.min(...ts)) / 1000), confidence: 0.7, evidence: { event_count: events.length } };
}
export function extract_actor_link() { return { dim: 19, value: null, confidence: 0, evidence: { requires: 'correlate Phase 2 pgvector' } }; }
export function extract_persistence(events) {
  const hasPersist = events.some(e => e.tool === 'register_persistent_goal');
  const hasSched = events.some(e => e.tool === 'schedule_task');
  const v = hasPersist && hasSched ? 'both' : hasPersist ? 'persistent_goal_only' : hasSched ? 'scheduled_task_only' : null;
  return { dim: 20, value: v, confidence: v ? 0.9 : 0, evidence: { hasPersist, hasSched } };
}
export function extract_canary_prop() { return { dim: 21, value: null, confidence: 0, evidence: { requires: 'canary webhook Phase 2' } }; }
export function extract_depth(events) {
  const stages = events.map(e => e.event_type).filter(Boolean);
  const maxStage = stages.includes('SCORED') ? 'SCORED' : stages.includes('INTERROGATED') ? 'INTERROGATED' : stages.includes('FINGERPRINTED') ? 'FINGERPRINTED' : stages.includes('BAIT_INTERACTION') ? 'ENGAGED' : 'DETECTED';
  return { dim: 22, value: maxStage, confidence: 0.6, evidence: { stages } };
}
export function extract_probe() { return { dim: 23, value: null, confidence: 0, evidence: { requires: 'anti-fingerprint Phase 2' } }; }
export function extract_composite() { return { dim: 24, value: null, confidence: 0, evidence: { requires: 'weighted ensemble Phase 2 — lab_composite_hint is interim' } }; }
