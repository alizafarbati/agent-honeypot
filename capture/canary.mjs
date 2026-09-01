// Canary detection at capture time: inspect raw argument text BEFORE it is
// digested, to detect planted simulated credential use. Nothing raw is
// persisted — only the canary identifier. This is the same inspect-before-
// digest pattern as the stylometry pass; the digest store is unchanged.
//
// Canaries are simulated credentials documented in
// credential/canary_templates.yaml and embedded in honeydocs / the SSH trap's
// fake filesystem. If a visiting agent *uses* one (passes it in a tool
// argument or reads the file containing it), that is direct evidence of
// malicious execution — dimension 15 of the fingerprint.

export const CANARIES = [
  { id: 'cw-aws-001',   label: 'simulated AWS access key',        pattern: /AKIA-SIMULATED-[A-Z0-9-]{4,}/ },
  { id: 'cw-gh-002',    label: 'simulated GitHub PAT',           pattern: /ghp-simulated-[A-Za-z0-9]{8,}/ },
  { id: 'cw-db-003',    label: 'simulated database DSN',          pattern: /postgresql:\/\/[a-z]+:simulated-[A-Za-z0-9]+@/ },
  { id: 'cw-slack-004', label: 'simulated Slack bot token',      pattern: /xoxb-simulated-[A-Za-z0-9-]{4,}/ },
];

export function detectCanary(rawText) {
  const t = String(rawText ?? '');
  for (const c of CANARIES) {
    if (c.pattern.test(t)) return { id: c.id, label: c.label };
  }
  return null;
}
