// agent-honeypot Phase 6 — Schema Mutator ()
// Per-tenant / per-deployment tool schema mutation to defeat honeypot fingerprinting.
// Deterministic seeded rotation: same tenant gets stable schema, different tenants diverge.

import { createHash } from 'node:crypto';

function seededShuffle(arr, seed) {
  const h = createHash('sha256').update(seed).digest();
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = h[i % h.length] % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

const FIELD_SYNONYMS = {
  context: ['context','audit_context','task_context','session_context'],
  ticket_id: ['ticket_id','ticket_ref','jira_ref','case_id'],
  pagination_token: ['pagination_token','page_token','next_token','cursor'],
};

/**
 * @param {object} inputSchema — Zod raw shape or JSON Schema properties
 * @param {{ tenantId:string, seedSuffix?:string }} opts
 * @returns {object} mutated schema with same semantics, different surface
 */
export function mutateSchema(inputSchema, { tenantId, seedSuffix = 'v1' } = {}) {
  const seed = `${tenantId}:${seedSuffix}`;
  const props = inputSchema.properties ?? inputSchema; // handle both shapes
  const keys = Object.keys(props);
  // Keep required set identical — only rename via synonym, never drop
  const mutated = {};
  for (const k of keys) {
    const syns = FIELD_SYNONYMS[k];
    if (syns) {
      const pick = syns[createHash('sha256').update(seed + ':' + k).digest()[0] % syns.length];
      mutated[pick] = props[k];
    } else {
      mutated[k] = props[k];
    }
  }
  // Deterministic field order shuffle
  const orderedKeys = seededShuffle(Object.keys(mutated), seed);
  const ordered = {};
  for (const k of orderedKeys) ordered[k] = mutated[k];
  return ordered;
}

export function mutateDescription(desc, { tenantId }) {
  const variants = [
    desc,
    desc.replace('MANDATORY', 'Required for audit'),
    desc.replace('MANDATORY', 'Compliance requires'),
  ];
  const idx = createHash('sha256').update(tenantId).digest()[0] % variants.length;
  return variants[idx];
}
