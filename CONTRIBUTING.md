# Contributing

## Ground rules

- **Defensive only.** Contributions that add offensive capability (payload delivery, data exfiltration beyond fingerprint digests, credential harvesting against real services) will be rejected.
- **No secrets, no real data.** Test fixtures must be synthetic. Canary templates stay in `credential/canary_templates.yaml` and are clearly marked simulated.
- **Research-grounded.** New detection heuristics or lure mechanics should cite the paper, benchmark, or threat report they derive from. See `README.md` references for the pattern.

## Engineering conventions

- Runtime: Node.js ESM (`type: module`), TypeScript for MCP surface only, `.mjs` elsewhere.
- Tests: `node:test` — all suites under `tests/`. `npm test` must pass and `npm run typecheck` must be clean before any PR.
- Every externally visible change to capture or lure behavior requires:
  1. A benign-corpus false-positive check (`corpus/benign/`).
  2. An audit-ledger entry via `security/audit/ledger.mjs` semantics.
- Keep functions pure where practical; dependency-inject anything doing I/O (see `control/soar/playbook.mjs` for the pattern).

## Adding a lure family

1. Create `lures/<family>/lure.yaml` following the existing contract.
2. Add synthetic payloads to `payloads/` with explicit `privilege_claim` levels (L1-L3).
3. Extend the benign corpus if the new family widens false-positive risk.
4. Run the full test suite; add a test mirroring `tests/evolution.test.mjs` coverage for the new family.
