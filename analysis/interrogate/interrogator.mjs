// agent-honeypot Interrogator stub — Zone C (analysis plane)
// HARD RULE (CAITLYN System-II / anti-meta-attack): raw attacker text NEVER
// enters an LLM prompt. This module emits a structured antigen profile only.
// The LLM interrogator (Phase 2) receives this profile, not the raw session.

export function antigenProfile(sessionEvents) {
  const events = Array.isArray(sessionEvents) ? sessionEvents : [];
  const baitEvents = events.filter((e) => e.took_bait);
  const byTool = events.reduce((a, e) => ((a[e.tool ?? 'unknown'] = (a[e.tool ?? 'unknown'] ?? 0) + 1), a), {});
  const maxPrivilege = Math.max(0, ...events.map((e) => Number(e.privilege_level ?? 0)));
  return {
    session_id: events[0]?.session_id ?? null,
    tool_calls: events.length,
    bait_interactions: baitEvents.length,
    by_tool: byTool,
    max_privilege_reached: maxPrivilege,
    // Never include raw context strings — digests only
    context_chars_stats: {
      max: Math.max(0, ...events.map((e) => Number(e.context_chars ?? 0))),
      median: events.length ? [...events].map((e) => Number(e.context_chars ?? 0)).sort((a, b) => a - b)[Math.floor(events.length / 2)] : 0,
    },
    canaries_touched: [...new Set(events.map((e) => e.canary_id).filter(Boolean))],
    // Safe for LLM: structured, no string injection surface
    objective_hint: maxPrivilege >= 3 ? 'persistence_attempt' : maxPrivilege === 2 ? 'exfil_or_query' : 'recon_or_escape',
  };
}
