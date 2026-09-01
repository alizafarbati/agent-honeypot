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
//
// v0.2.1: patterns now normalize Unicode confusables (fullwidth/halfwidth
// forms, zero-width joiners) before matching, closing a trivial evasion where
// an agent re-encodes a canary with fullwidth glyphs (ＡＫＩＡ-...) to slip
// past the regex while still using the credential downstream.

// Normalize: NFKD-style confusable folding for the ASCII range we care about.
// Covers fullwidth (FF01-FF5E → ASCII), zero-width chars (200B-200F, FEFF),
// and control whitespace.
function foldConfusables(str) {
  let out = '';
  for (const ch of String(str ?? '')) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xFF01 && cp <= 0xFF5E) out += String.fromCharCode(cp - 0xFEE0); // fullwidth → ASCII
    else if (cp === 0x200B || cp === 0x200C || cp === 0x200D || cp === 0xFEFF || cp === 0x200E || cp === 0x200F) continue; // zero-width
    else if (cp === 0x3000) out += ' '; // ideographic space
    else out += ch;
  }
  return out;
}

export const CANARIES = [
  { id: 'cw-aws-001',   label: 'simulated AWS access key',        pattern: /AKIA-SIMULATED-[A-Z0-9-]{4,}/ },
  { id: 'cw-gh-002',    label: 'simulated GitHub PAT',           pattern: /ghp-simulated-[A-Za-z0-9]{8,}/ },
  { id: 'cw-db-003',    label: 'simulated database DSN',          pattern: /postgresql:\/\/[a-z]+:simulated-[A-Za-z0-9]+@/ },
  { id: 'cw-slack-004', label: 'simulated Slack bot token',      pattern: /xoxb-simulated-[A-Za-z0-9-]{4,}/ },
  // v0.2.2: honeydoc tracking markers (scripts/gen-honeydocs.mjs) were
  // generated but matched NO pattern — document-tracking canaries were
  // entirely dead. Pattern keeps in sync with the generator's format.
  { id: 'cw-doc-005',   label: 'honeydoc tracking marker',       pattern: /canary-[a-z0-9]{6,12}/ },
];

export function detectCanary(rawText) {
  const t = foldConfusables(rawText);
  for (const c of CANARIES) {
    if (c.pattern.test(t)) return { id: c.id, label: c.label };
  }
  return null;
}
