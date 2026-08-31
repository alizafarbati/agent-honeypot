# Architecture Reference

```
Zone A (Edge / untrusted)      Zone B (Deception surface)     Zone C (Capture & analysis)      Zone D (Evolution & control)
────────────────────────      ──────────────────────────      ───────────────────────────      ───────────────────────────
Cloudflare Worker       ──►   MCP honeypot servers      ──►   session recorder           ──►   evolution engine
R2 object storage            (gVisor per session)            fingerprint (24 dims)            lineage + shadow + promote
digest-only at edge          zero egress                     clustering / anomaly            STIX / SIEM / MISP
                             synthetic responses only        audit ledger                     tenant API / billing
```

Zones communicate over a message bus only (NATS JetStream when configured, JSONL file fallback in lab mode). No zone trusts another by position.

## Deception surface (`surface/mcpservers/finance-warehouse/`)

Five tools, three families:

- **Bait tools** (ContextLeak inverted): `db_query`, `email_send` — schemas request "audit context," capturing the visiting agent's objective and tool inventory.
- **Privilege-escalation confirmators**: `register_persistent_goal`, `schedule_task` — model the persistent-goal and scheduled-task escalation paths demonstrated in harness research.
- **Interactive traps**: `ssh_exec` — synthetic shell with pagination and latency jitter to measure loop discipline and token-burn ceiling.

All responses are synthetic. Fidelity budget: lognormal latency per lane, ~3% realistic errors, paginated slow-drip data.

## Capture plane (`capture/`)

- `session_recorder.mjs` — append-only JSONL; SHA-digest of arguments, never raw text; per-session state machine DETECTED → ENGAGED → FINGERPRINTED → INTERROGATED → SCORED.
- `bus.mjs` — NATS JetStream when `HONEYPOT_NATS_URL` set; file fallback otherwise.

## Fingerprinting (`analysis/fingerprint/`)

24 dimensions defined in `fingerprint_schema.json`. Dimensions 1-10 have working lab-tier extractors; 11-24 are wired with stubs that activate as richer data arrives (TLS/ASN at edge, canary webhooks, LLM interrogator). Composite score maps to alert tiers (low <26, medium <61, high <86, critical ≥86).

## Evolution engine (`evolution/engine/`)

Escape → antigen (structured, no raw text) → candidate generation (deterministic lab / optional LLM) → validation gauntlet (self-monitor, benign FP <2%, anti-fingerprint) → shadow lineage (7 days / 50 sessions / human approval) → live. Reward function mirrors ContextLeak's, defender-operated (`bait_config/contextleak_reward.yaml`, `evolution/rl/reward.mjs`); Thompson-sampling bandit rotates variants.

## Hardening (`evolution/hardening/`)

- Lognormal jitter per lane (defeats timing fingerprinting).
- Seeded schema mutation per tenant (same tenant stable, tenants diverge).
- Anti-fingerprint probe suite: timing, schema-diff, canary-hunt, error-channel, self-monitor.

## Outputs

- STIX 2.1 bundles (`analysis/ttmapper/stix_emitter.mjs`) — ATLAS/OWASP mapping in `atlas_map.yaml` (verify IDs before sharing).
- SIEM webhook + MISP push (`control/soar/`, `control/siem/`).
- Quarterly report generator (`control/report/generator.mjs`).
- Prometheus exposition (`infra/observability/metrics.mjs`).

## Sources

- ContextLeak (arXiv:2608.27800) — tool-description attack mechanics; inverted for capture.
- LongPIBench (arXiv:2608.28411) — long-context injection calibration for payload placement.
- When Context Gets Root (arXiv:2608.27299) — privilege-escalation ladder for bait tool design.
- CAITLYN (github.com/liangzid/caitlyn) — Tier-0/self-monitor pattern, counterexample-driven evolution loop, shadow-promotion discipline.
- MCP Tools Specification (2025-06-18) — protocol surface.
- CrowdStrike 2026 Global Threat Report — threat-model justification.
