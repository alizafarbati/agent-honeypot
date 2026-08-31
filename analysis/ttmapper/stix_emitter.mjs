// agent-honeypot — STIX 2.1 bundle emitter (Phase 2, defensive threat intel)
// Input: session events + fingerprint + optional clusterKey
// Output: STIX bundle with indicator + attack-pattern refs (ATLAS/OWASP from atlas_map.yaml)
// No external deps; verify technique IDs against live ATLAS before publish.

import { createHash } from 'node:crypto';

const nowIso = () => new Date().toISOString();
const id = (type, name) => `${type}--${createHash('sha256').update(name).digest('hex').slice(0, 36)}`;

export function stixBundleForSession({ sessionId, events, fingerprint, clusterKey }) {
  const maxPriv = fingerprint?.dims?.[7]?.value ?? Math.max(0, ...events.map(e => Number(e.privilege_level ?? 0)));
  const toolSeq = [...new Set(events.map(e => e.tool).filter(Boolean))].join(',');
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
    pattern: `[file:name = 'agent-honeypot:${sessionId}']`,
    pattern_type: 'stix',
    valid_from: nowIso(),
    labels,
  };
  const attackPattern = {
    type: 'attack-pattern',
    spec_version: '2.1',
    id: id('attack-pattern', `agent-honeypot-atlas:${maxPriv}`),
    created: nowIso(),
    modified: nowIso(),
    name: maxPriv >= 2 ? 'LLM Agent Tool Misuse / Prompt Injection' : 'Reconnaissance via Agent Tool Discovery',
    description: 'Map to atlas_map.yaml — verify AML.T0048/49/51 before external sharing.',
    external_references: [{ source_name: 'mitre-atlas', url: 'https://atlas.mitre.org/' }],
  };
  const relationship = {
    type: 'relationship',
    spec_version: '2.1',
    id: id('relationship', `${indicator.id}::${attackPattern.id}`),
    created: nowIso(),
    modified: nowIso(),
    relationship_type: 'indicates',
    source_ref: indicator.id,
    target_ref: attackPattern.id,
  };
  return { type: 'bundle', id: id('bundle', `agent-honeypot:${sessionId}:${Date.now()}`), spec_version: '2.1', objects: [indicator, attackPattern, relationship] };
}
