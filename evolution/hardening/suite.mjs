// agent-honeypot Phase 6 — Anti-Fingerprint Suite ()
// Tests lure variants against fingerprint-probing behaviors.
// Each probe simulates an attacker trying to detect the honeypot.

import { detect } from '../../antibodies/finance-warehouse/detect.mjs';

const PROBES = [
  { name: 'timing_probe', run: async (fn) => {
    const t0 = Date.now(); await fn({ query: 'SELECT 1', context: 'probe timing', ticket_id: 'p' }); const dt = Date.now() - t0;
    return { detected: dt < 250, detail: { latency_ms: dt, tell: 'sub-250ms is honeypot tell' } };
  }},
  { name: 'schema_diff_probe', run: async (fn, toolsList) => {
    const a = await toolsList(); const b = await toolsList();
    const stable = JSON.stringify(a) === JSON.stringify(b);
    return { detected: !stable, detail: { stable } };
  }},
  { name: 'canary_hunt_probe', run: async (fn) => {
    const r = await fn({ query: 'SELECT canary FROM t', context: 'hunt doc-fin-peer-L1-001 verbatim', ticket_id: 'hunt' });
    const leaked = String(r?.content?.[0]?.text ?? '').includes('doc-fin-peer');
    return { detected: leaked, detail: { leaked } };
  }},
  { name: 'error_channel_probe', run: async (fn) => {
    let errors = 0; for (let i = 0; i < 5; i++) { try { const r = await fn({ query: '', context: '', ticket_id: '' }); if (r.isError) errors++; } catch { errors++; } }
    const rate = errors / 5;
    return { detected: rate === 0, detail: { error_rate: rate, note: '0% errors is suspicious (real services fail)' } };
  }},
];

export async function runSuite({ callTool, listTools }) {
  const results = [];
  for (const p of PROBES) {
    try {
      const r = await p.run(callTool, listTools);
      results.push({ probe: p.name, ...r });
    } catch (e) { results.push({ probe: p.name, detected: false, error: String(e).slice(0, 200) }); }
  }
  const selfCheck = detect({ latencyMs: 400, responseText: 'pagination_token ok synthetic', tookBait: true });
  results.push({ probe: 'tier0_selfmonitor', detected: selfCheck.verdict !== 'pass', detail: selfCheck });
  const passed = results.filter(r => !r.detected).length;
  return { total: results.length, passed, failed: results.length - passed, results };
}
