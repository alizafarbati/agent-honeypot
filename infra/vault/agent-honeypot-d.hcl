# Vault policy — Zone D (evolution/control) — lineage promotion + audit
path "secret/data/agent-honeypot/analysis/*"  { capabilities = ["read", "update"] }
path "secret/data/agent-honeypot/lures/*"     { capabilities = ["read", "create", "update", "delete"] }
path "secret/data/agent-honeypot/lineage/*"   { capabilities = ["read", "create", "update"] }
path "secret/data/agent-honeypot/audit/*"     { capabilities = ["read", "create"] }
path "secret/data/agent-honeypot/siem/*"      { capabilities = ["read", "update"] }
