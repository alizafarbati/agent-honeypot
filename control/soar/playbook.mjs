// agent-honeypot Phase 7 — SOAR Playbook Engine ()
// Automated response playbooks triggered by severity. Defensive only: observe / stall / isolate.
// Each playbook is audited; no destructive actions.

const PLAYBOOKS = {
  low:  { actions: ['log'], notify: false },
  medium: { actions: ['log','fingerprint_enrich'], notify: false },
  high: { actions: ['log','fingerprint_enrich','stix_emit','siem_dispatch'], notify: true },
  critical: { actions: ['log','fingerprint_enrich','stix_emit','siem_dispatch','tenant_quarantine_shadow'], notify: true },
};

export function severityFromComposite(score) {
  if (score >= 86) return 'critical';
  if (score >= 61) return 'high';
  if (score >= 26) return 'medium';
  return 'low';
}

export async function runPlaybook({ sessionId, compositeScore, events, tenantId }, deps = {}) {
  const severity = severityFromComposite(compositeScore ?? 0);
  const plan = PLAYBOOKS[severity];
  const executed = [];
  for (const a of plan.actions) {
    if (a === 'log') executed.push({ action: a, ok: true });
    else if (a === 'fingerprint_enrich' && deps.fingerprint) { try { await deps.fingerprint(events); executed.push({ action: a, ok: true }); } catch (e) { executed.push({ action: a, ok: false, error: String(e).slice(0,150) }); } }
    else if (a === 'stix_emit' && deps.stix) { try { await deps.stix({ sessionId, events }); executed.push({ action: a, ok: true }); } catch (e) { executed.push({ action: a, ok: false, error: String(e).slice(0,150) }); } }
    else if (a === 'siem_dispatch' && deps.siem) { try { await deps.siem({ sessionId, severity }); executed.push({ action: a, ok: true }); } catch (e) { executed.push({ action: a, ok: false, error: String(e).slice(0,150) }); } }
    else if (a === 'tenant_quarantine_shadow' && deps.quarantine) { try { await deps.quarantine(tenantId); executed.push({ action: a, ok: true }); } catch (e) { executed.push({ action: a, ok: false, error: String(e).slice(0,150) }); } }
    else executed.push({ action: a, ok: null, note: 'no handler injected (lab)' });
  }
  return { session_id: sessionId, severity, plan: plan.actions, executed, notify: plan.notify };
}
