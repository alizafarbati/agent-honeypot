# Vault policies — agent-honeypot (Phase 2 dynamic secrets)
# Apply with: vault policy write agent-honeypot-b - < vault/agent-honeypot-b.hcl  etc.
# Lab tier: file JSONL persistence; Enterprise: Vault Agent sidecar injects dynamic creds.

# Zone B (deception surface) — read-only session token, no lure mutation
path "secret/data/agent-honeypot/session/*" {
  capabilities = ["read"]
  allowed_parameters = { "session_id" = [] }
}

# Zone C (capture/analysis) — read+update analysis + lures (fingerprint, SIEM)
path "secret/data/agent-honeypot/analysis/*" { capabilities = ["read", "update"] }
path "secret/data/agent-honeypot/lures/*"     { capabilities = ["read"] }
path "secret/data/agent-honeypot/siem/*"      { capabilities = ["read"] }

# Zone D (evolution/control) — full lineage + promotion + audit
# Separate file: vault/agent-honeypot-d.hcl
