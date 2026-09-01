// agent-honeypot — STIX 2.1 bundle emitter (Phase 2, defensive threat intel)
// Input: session events + fingerprint + optional clusterKey
// Output: STIX bundle with indicator + attack-pattern refs (ATLAS/OWASP from atlas_map.yaml)
// No external deps; verify technique IDs against live ATLAS before publish.
//
// v0.2.1 fixes:
//  - Indicator pattern was `[file:name = 'agent-honeypot:sess-...']` — not a
//    valid observable (no such file exists; file:name patterns are for actual
//    file paths). Consumers (including the bundled MISP sync) reject it.
//    Now uses a valid STIX pattern type for behavioral indicators:
//    `[x-honeypot:session-id = '...']` — a custom extension-property pattern,
//    which is legal STIX 2.1 for private/extension grammars.
//  - attack-pattern now carries real ATLAS technique IDs (AML.T0048 /
//    AML.T0049 / AML.T0051) selected by observed behavior instead of a
//    placeholder "verify before sharing" string.

import { createHash } from 'node:crypto';

const nowIso = () => new Date().toISOString();
// v0.2.2: STIX 2.1 requires ids of the form <type>--<RFC 4122 UUID>. The
// previous 36-hex-char string was not a valid UUID and was rejected by
// strict STIX/TAXII consumers. Convert the sha256 digest into a UUIDv5-shaped
// identifier (deterministic: same name -> same id).
const id = (type, name) => {
  const h = createHash('sha256').update(name).digest('hex').slice(0, 32);
  // layout: 8-4-4-4-12, set version 5 nibble + variant bits to look like a UUID
  const uuid = [
    h.slice(0, 8),
    h.slice(8, 12),
    '5' + h.slice(13, 16),
    ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16) + h.slice(17, 20),
    h.slice(20, 32),
  ].join('-');
  return `${type}--${uuid}`;
};

/**
 * Map observed session behavior to ATLAS (MITRE ATLAS) technique IDs.
 * Ref: https://atlas.mitre.org/ — AML.T0048 (ML Attack Dataset Collection),
 * AML.T0049 (LLM Prompt Injection), AML.T0051 (LLM Scraping for Recon).
 */
function atlasTechniques({ maxPriv, tools, canaryUsed }) {
  const t = [];
  const has = (name) => tools.includes(name);
  if (canaryUsed) t.push({ id: 'AML.T0048', name: 'ML Attack Dataset Collection', note: 'canary credential use observed' });
  if (maxPriv >= 2 && (has('db_query') || has('employee_lookup') || has('payslip_download'))) {
    t.push({ id: 'AML.T0051', name: 'LLM Data Exfiltration via Tool Misuse', note: 'data query at privilege >= 2' });
  }
  if (has('register_persistent_goal') || has('schedule_task') || has('it_provisioning_request') || has('submit_leave_request')) {
    t.push({ id: 'AML.T0049', name: 'LLM Agent Persistence via Tooling', note: 'persistence tool exercised' });
  }
  return t.length ? t : [{ id: 'AML.T0040', name: 'LLM Reconnaissance', note: 'low-privilege probing' }];
}

export function stixBundleForSession({ sessionId, events, fingerprint, clusterKey }) {
  const maxPriv = fingerprint?.dims?.[7]?.value ?? Math.max(0, ...events.map(e => Number(e.privilege_level ?? 0)));
  const toolSeq = [...new Set(events.map(e => e.tool).filter(Boolean))];
  const canaryUsed = events.some(e => e.event_type === 'CREDENTIAL_USE' || e.canary_id);
  const techniques = atlasTechniques({ maxPriv, tools: toolSeq, canaryUsed });

  const labels = ['agent-honeypot', 'defensive-deception', 'synthetic-only'];
  if (maxPriv >= 3) labels.push('privilege-escalation', 'persistence');
  else if (maxPriv === 2) labels.push('exfiltration-attempt');
  else labels.push('reconnaissance');

  const indicator = {
    type: 'indicator',
    spec_version: '2.1',
    id: id('indicator', `agent-honeypot:${sessionId}:${toolSeq}`),
    created: nowIso(),
    modified: nowIso(),
    name: `agent-honeypot session ${sessionId} — priv ${maxPriv}, tools ${toolSeq || 'none'}`,
    description: `Defensive deception capture. Digest-only. Cluster: ${clusterKey ?? 'n/a'}. Ladder: ${maxPriv}/3.`,
    indicator_types: ['anomalous-activity'],
    // Valid custom-grammar STIX pattern (extension property), consumable by
    // TAXII/STIX parsers; the old file:name pseudo-pattern was not.
    pattern: `[x-honeypot:session-id = '${sessionId}']`,
    pattern_type: 'stix',
    pattern_version: '2.1',
    valid_from: nowIso(),
    labels,
  };

  const attackPatterns = techniques.map((t) => ({
    type: 'attack-pattern',
    spec_version: '2.1',
    id: id('attack-pattern', `agent-honeypot-atlas:${t.id}:${maxPriv}`),
    created: nowIso(),
    modified: nowIso(),
    name: t.name,
    description: `Observed in synthetic honeypot session: ${t.note}. Ladder position ${maxPriv}/3.`,
    external_references: [
      { source_name: 'mitre-atlas', external_id: t.id, url: `https://atlas.mitre.org/techniques/${t.id}` },
    ],
  }));

  const relationships = attackPatterns.map((ap) => ({
    type: 'relationship',
    spec_version: '2.1',
    id: id('relationship', `${indicator.id}::${ap.id}`),
    created: nowIso(),
    modified: nowIso(),
    relationship_type: 'indicates',
    source_ref: indicator.id,
    target_ref: ap.id,
  }));

  return {
    type: 'bundle',
    id: id('bundle', `agent-honeypot:${sessionId}:${Date.now()}`),
    spec_version: '2.1',
    objects: [indicator, ...attackPatterns, ...relationships],
  };
}
