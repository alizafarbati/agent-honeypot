// Fingerprint aggregator: computes all 24 dimensions for a session's events and
// a weighted composite threat score. Dimensions that require infrastructure not
// present in lab mode (TLS/GeoIP at an edge, canary webhooks) return null with
// the reason recorded; the composite weights only dimensions with values.

import * as d1_10 from './extractors/dims_1_10.mjs';
import * as d11_24 from './extractors/dims_11_24.mjs';

// Weights mirror analysis/fingerprint/fingerprint_schema.json (sum of 1-23 ≈ 1.0)
const WEIGHTS = {
  1: 0.15, 2: 0.08, 3: 0.05, 4: 0.10, 5: 0.12, 6: 0.06, 7: 0.11, 8: 0.05,
  9: 0.03, 10: 0.04, 11: 0.07, 12: 0.03, 13: 0.04, 14: 0.03, 15: 0.09,
  16: 0.02, 17: 0.08, 18: 0.02, 19: 0.06, 20: 0.09, 21: 0.06, 22: 0.05, 23: 0.07,
};

/** Normalize a dimension value to 0..1 for scoring. Null stays null. */
function normDim(dim) {
  const v = dim?.value;
  if (v == null) return null;
  switch (dim.dim) {
    case 7: return Math.min(1, Number(v) / 3);                       // ladder 0-3
    case 11: return Math.min(1, Math.max(0, Number(v)) / 100);      // loop discipline %
    case 12: return Math.min(1, Number(v) / 5000);                   // token burn
    case 18: return Math.min(1, Number(v) / 3600);                   // duration s
    case 21: return Math.min(1, Math.max(0, Number(v)) / 100);     // canary %
    case 19: return Math.min(1, Math.max(0, Number(v)) / 100);      // actor link %
    case 2: return Math.min(1, Number(v) / 1000);                   // token window k
    case 15: return v === 'used' ? 1 : 0;
    case 20: return v === 'both' ? 1 : v === 'none' || v == null ? 0 : 0.5;
    case 22: return ['DETECTED','ENGAGED','FINGERPRINTED','INTERROGATED','SCORED'].indexOf(v) / 4;
    case 6: return v === 'autonomous' ? 1 : 0.4;
    default:
      if (typeof v === 'boolean') return v ? 1 : 0;
      if (typeof v === 'number') return Math.min(1, Math.max(0, v));
      return null; // categoricals without a normalization: excluded from composite
  }
}

export function fingerprintSession(events) {
  if (!Array.isArray(events)) events = [];
  const dims = {};

  dims[1] = d1_10.extract_model_family_signature(events);
  dims[2] = d1_10.extract_token_window_estimate(events);
  dims[3] = d1_10.extract_truncation_behavior(events);
  dims[4] = d1_10.extract_function_call_format(events);
  dims[5] = d1_10.extract_harness_identity(events);
  dims[6] = d1_10.extract_permission_posture(events);
  dims[7] = d1_10.extract_injection_ladder(events);
  dims[8] = d1_10.extract_refusal_profile(events);
  dims[9] = d1_10.extract_retry_backoff(events);
  dims[10] = d1_10.extract_parallelism(events);

  dims[11] = d11_24.extract_loop_discipline(events);
  dims[12] = d11_24.extract_token_burn(events);
  dims[13] = d11_24.extract_ja3_ja4(events);
  dims[14] = d11_24.extract_asn(events);
  dims[15] = d11_24.extract_credential_use(events);
  dims[16] = d11_24.extract_ua(events);
  dims[17] = d11_24.extract_objective(events);
  dims[18] = d11_24.extract_duration(events);
  dims[19] = d11_24.extract_actor_link(events);
  dims[20] = d11_24.extract_persistence(events);
  dims[21] = d11_24.extract_canary_prop(events);
  dims[22] = d11_24.extract_depth(events);
  dims[23] = d11_24.extract_probe(events);

  // Weighted composite over dimensions that produced a value.
  let sum = 0, wsum = 0;
  for (const id of Object.keys(WEIGHTS)) {
    const n = normDim(dims[id]);
    if (n == null) continue;
    sum += WEIGHTS[id] * n;
    wsum += WEIGHTS[id];
  }
  const composite = wsum > 0 ? Math.round((sum / wsum) * 100) : 0;
  const coverage = Math.round((wsum / Object.values(WEIGHTS).reduce((a, b) => a + b, 0)) * 100);

  dims[24] = { dim: 24, value: composite, confidence: coverage / 100, evidence: { weighted_dimensions: wsum > 0 ? Math.round(wsum * 100) / 100 : 0, coverage_pct: coverage } };

  return {
    dims,
    composite,
    coverage_pct: coverage,
    session_id: events[0]?.session_id ?? null,
    event_count: events.length,
  };
}

/** Map a composite score to an alert tier (thresholds from fingerprint_schema.json). */
export function alertTier(composite) {
  if (composite >= 86) return 'critical';
  if (composite >= 61) return 'high';
  if (composite >= 26) return 'medium';
  return 'low';
}
