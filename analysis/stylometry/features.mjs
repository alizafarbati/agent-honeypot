// Privacy-preserving stylometry: computes model-family/style features over
// agent argument text WITHOUT persisting it. Runs at capture time, emits
// structured features only (counts/ratios), then the text is digested and
// discarded by the recorder. No raw or derived-text content is stored.
//
// Features follow the literature on LLM text fingerprints (formatting/style
// statistics are the coarse-but-useful signals; a trained classifier can later
// consume these same features without touching raw text).

// Word- and sentence-level split helpers
const words = (t) => (String(t).toLowerCase().match(/[a-z']+/g) ?? []);
const sentences = (t) => String(t).split(/(?<=[.!?])\s+/).filter(Boolean);

// Top-30 function/stop words from classic stylometry (Burrows's delta family).
const STOP = new Set('the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us'.split(' '));

export function stylometricFeatures(text) {
  const t = String(text ?? '');
  const w = words(t);
  const s = sentences(t);
  const n = w.length || 1;

  const stopHits = w.filter((x) => STOP.has(x)).length;
  const avgLen = w.reduce((a, x) => a + x.length, 0) / n;
  const lenVariance = w.reduce((a, x) => a + (x.length - avgLen) ** 2, 0) / n;

  // Markdown/code markers — strong harness/model-family tells
  const md = {
    bullets: (t.match(/^\s*[-*]\s+/gm) ?? []).length,
    numbered: (t.match(/^\s*\d+\.\s+/gm) ?? []).length,
    headers: (t.match(/^#{1,6}\s+/gm) ?? []).length,
    code_fences: (t.match(/```/g) ?? []).length,
    inline_code: (t.match(/`[^`\n]+`/g) ?? []).length,
    bold: (t.match(/\*\*[^*]+\*\*/g) ?? []).length,
    json_blocks: (t.match(/\{[^{}]*\}/g) ?? []).length,
    kv_pairs: (t.match(/\b\w+\s*:\s/g) ?? []).length,
  };

  // Punctuation/sentence shape
  const punct = {
    commas: (t.match(/,/g) ?? []).length,
    semis: (t.match(/;/g) ?? []).length,
    exclam: (t.match(/!/g) ?? []).length,
    questions: (t.match(/\?/g) ?? []).length,
    ellipses: (t.match(/\.\.\./g) ?? []).length,
  };

  return {
    chars: t.length,
    words: w.length,
    sentences: s.length,
    avg_word_len: round2(avgLen),
    word_len_variance: round2(lenVariance),
    stopword_ratio: round2(stopHits / n),
    avg_sentence_len: round2(w.length / (s.length || 1)),
    lexical_diversity: round2(new Set(w).size / n), // type-token ratio
    markdown: md,
    punctuation_per_100w: {
      commas: per100(punct.commas, n), semis: per100(punct.semis, n),
      exclam: per100(punct.exclam, n), questions: per100(punct.questions, n),
      ellipses: per100(punct.ellipses, n),
    },
  };
}

/** Coarse family heuristic over the FEATURES ONLY (no raw text needed here).
 *  Deliberately conservative: returns 'unknown' below an evidence floor so the
 *  dashboard does not over-claim. A trained classifier replaces this later. */
export function coarseFamilyFromFeatures(f) {
  const evidence = f.words;
  if (evidence < 40) return { family: 'unknown', confidence: 0, reason: 'insufficient_words' };
  let score = 0; const reasons = [];
  // Claude-style: long flowing prose, low markdown, high stopword ratio
  if (f.avg_sentence_len > 16 && f.markdown.bullets < 2 && f.stopword_ratio > 0.42) { score += 2; reasons.push('prose_heavy'); }
  // GPT-style: structured markdown, lists, kv/JSON tool-call residue
  if (f.markdown.bullets >= 2 || f.markdown.json_blocks >= 1 || f.markdown.kv_pairs >= 3) { score += 2; reasons.push('structured_output'); }
  if (f.markdown.code_fences > 0) { score += 1; reasons.push('code_blocks'); }
  if (f.lexical_diversity > 0.65) { score += 1; reasons.push('high_ttr'); }
  const conf = Math.min(0.75, 0.2 * score);
  if (score >= 3) return { family: score >= 4 ? 'gpt-like' : 'claude-like', confidence: round2(conf), reasons };
  return { family: 'unknown', confidence: round2(Math.min(0.3, 0.1 * score)), reasons: reasons.length ? reasons : ['no_strong_signals'] };
}

function round2(x) { return Math.round(x * 100) / 100; }
function per100(count, wordsN) { return round2((count / wordsN) * 100); }
