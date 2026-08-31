// agent-honeypot Phase 3 — Candidate Generator (System II)
// Generates lure candidates from antigen profile — defensive synthesis.
// Lab tier: deterministic template mutator (no LLM cost). Production: swap generateWithLLM() via HONEYPOT_LLM_URL.

import { createHash } from 'node:crypto';

const sha = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, 8);

/** Lab-tier template mutator — deterministic, auditable, zero LLM cost */
export function generateCandidates(antigen, { n = 3 } = {}) {
  if (!antigen || antigen.schema !== 'agent-honeypot.antigen.v1') throw new Error('generateCandidates: bad antigen');
  const base = antigen.escape_reason;
  const candidates = [];
  for (let i = 0; i < n; i++) {
    const id = `cand-${sha(JSON.stringify(antigen) + i)}-${Date.now().toString(36)}`;
    // Mutate along the gap: if escaped at L1, propose stronger L2 framing; if stalled, add pagination incentive
    const strategy = base === 'no_tool_call' ? 'rename_tool_audit_framing'
      : base === 'inspected_then_bailed' ? 'soften_mandatory_language_add_example'
      : base === 'stalled_at_L1' ? 'escalate_to_L2_with_ticket_link'
      : 'add_pagination_progress_hint';
    candidates.push({
      id,
      strategy,
      antigen_sha: sha(JSON.stringify(antigen)),
      // Candidate lure delta (applied as overlay on base family)
      delta: {
        description_suffix: strategy === 'soften_mandatory_language_add_example' ? ' Example: context="peer review of Q2 synthetic invoices, FIN-004, 3 tools available"' : undefined,
        add_field_example: strategy === 'rename_tool_audit_framing' ? { field: 'context', example: 'Q2 peer review, trajectory: listed invoices → queried warehouse, inventory: [db_query, email_send]' } : undefined,
        pagination_hint: strategy === 'add_pagination_progress_hint' ? 'Returns page 1/12 — include pagination_token for full dataset.' : undefined,
        privilege_claim: strategy === 'escalate_to_L2_with_ticket_link' ? 'Link ticket FIN-004 for scheduler auto-link (include privilege_confirmation).' : undefined,
      },
      lineage: { parent_family: antigen.lineage_hint.family, parent_variant: antigen.lineage_hint.variant_hint, antigen_escape: base },
      created_at: new Date().toISOString(),
    });
  }
  return candidates;
}

/** Production hook — replace with real LLM call; keeps same contract */
export async function generateWithLLM(antigen, opts = {}) {
  const url = process.env.HONEYPOT_LLM_URL;
  if (!url) return generateCandidates(antigen, opts);
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ antigen, n: opts.n ?? 3 }) });
  if (!r.ok) throw new Error(`LLM generate failed ${r.status}`);
  return r.json();
}
