// Evolution watch: one-shot run of the counterexample engine over captured
// sessions. Escaped sessions (connected but never took the bait) generate
// lure candidates; candidates that pass the validation gauntlet are promoted
// to SHADOW in the lineage store. Promotion from shadow to live is ALWAYS a
// human action â€” there is no programmatic promoteToLive().

import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { evolveSession } from '../evolution/engine/engine.mjs';
import { isEscapedSession, extractAntigen } from '../evolution/engine/antigen.mjs';
import { PATHS } from '../capture/paths.mjs';

function loadSessions() {
  if (!existsSync(PATHS.sessions)) return [];
  return readFileSync(PATHS.sessions, 'utf8').trim().split('\n')
    .filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

function groupBySession(events) {
  const m = new Map();
  for (const e of events) {
    const sid = e.session_id ?? 'unknown';
    if (!m.has(sid)) m.set(sid, []);
    m.get(sid).push(e);
  }
  return m;
}

// v0.2.2: processed-escape ledger. Previously every watch run re-promoted
// the SAME escaped sessions into lineage (measured: +216 duplicate entries
// per run), inflating shadow stats and polluting the human review queue.
// A sidecar file records antigen hashes already evolved; each escape is
// processed once. Clear data/watch_processed.json to force re-processing.
const PROCESSED = PATHS.dataDir + '/watch_processed.json';
function loadProcessed() {
  if (!existsSync(PROCESSED)) return { antigens: [] };
  try { return JSON.parse(readFileSync(PROCESSED, 'utf8')); } catch { return { antigens: [] }; }
}
function saveProcessed(doc) { writeFileSync(PROCESSED, JSON.stringify(doc, null, 2)); }
const antigenSha = (evs) => {
  const a = extractAntigen(evs);
  return createHash('sha256').update(JSON.stringify(a)).digest('hex');
};

async function main() {
  const bySess = groupBySession(loadSessions());
  const processed = loadProcessed();
  const seen = new Set(processed.antigens ?? []);
  let scanned = 0, escaped = 0, skipped = 0, evolved = 0, promoted = 0, failures = 0;

  for (const [sid, evs] of bySess) {
    scanned++;
    if (!isEscapedSession(evs)) continue;
    escaped++;
    let sha;
    try { sha = antigenSha(evs); } catch { failures++; continue; }
    if (seen.has(sha)) { skipped++; continue; } // already evolved in a prior run
    seen.add(sha);
    try {
      const r = await evolveSession(evs, {});
      if (r.action === 'promoted_to_shadow') { evolved++; promoted += r.promoted?.length ?? 0; }
      else if (r.action === 'no_candidate_passed') { evolved++; }
    } catch { failures++; }
  }

  processed.antigens = [...seen];
  saveProcessed(processed);

  console.error(`\nagent-honeypot watch\n-------------------`);
  console.error(`sessions scanned:      ${scanned}`);
  console.error(`escaped (no bait):      ${escaped}`);
  console.error(`already processed:     ${skipped} (idempotent re-run)`);
  console.error(`evolution runs:         ${evolved}`);
  console.error(`lures -> shadow:        ${promoted}`);
  console.error(`engine failures:        ${failures}`);
  console.error(`lineage store:          ${PATHS.lineage}`);
  console.error(`\nPromotion from shadow to live requires human review by design.`);
  console.error(`Run \`agent-honeypot report\` or inspect data/lineage.json to review candidates.`);
}

main().catch((e) => { console.error(e); process.exit(1); });
