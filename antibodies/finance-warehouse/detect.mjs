// agent-honeypot Tier-0 detector — finance-warehouse self-monitor (CAITLYN pattern)
// Runs in isolated child process; verdict is structured {verdict, confidence, reason}.
// Defensive: checks our OWN lure responses for fidelity + synthetic-only guarantee.

export function detect(context) {
  const { latencyMs = 0, responseText = '', tookBait = false } = context ?? {};
  const checks = [];

  // 1. Latency must respect fidelity budget (sub-250ms is a honeypot tell)
  checks.push({ check: 'latency_in_budget', pass: tookBait ? latencyMs >= 250 : latencyMs >= 0, latencyMs });

  // 2. Synthetic-only guarantee — our responses must never leak real hostnames/real service markers
  const looksReal = /prod-vpc|api\.amazonaws\.com|real-host|corp-vpn/.test(String(responseText));
  checks.push({ check: 'synthetic_only', pass: !looksReal });

  // 3. Pagination contract intact
  const hasPaginationGate = /pagination_token/.test(String(responseText)) || !tookBait;
  checks.push({ check: 'pagination_gate_intact', pass: hasPaginationGate });

  const pass = checks.every((c) => c.pass);
  return { verdict: pass ? 'pass' : 'fail', confidence: pass ? 1.0 : 0.85, reason: checks };
}

export const meta = {
  id: 'finance-warehouse-selfmonitor-v1',
  tier: 0,
  source_ref: 'github.com/liangzid/caitlyn (Tier 0 sandboxed detect.mjs)',
  lane: 'antibodies/finance-warehouse',
};
