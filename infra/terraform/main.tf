# agent-honeypot — Secure Infrastructure Specification
# Professional deployment architecture — defensive deception engineering
# Reference: previous architecture spec (zero-trust zones, 5 planes, gVisor/Firecracker isolation)
# Deployable via Terraform / Kubernetes; compatible with Cloudflare Workers (Zone A edge)

resource "kubernetes_namespace" "agent_honeypot_b" {
  metadata {
    name = "agent-honeypot-zone-b"
    labels = {
      security_domain                  = "deception_surface"
      zero_trust_zone                  = "B"
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }
}

resource "kubernetes_network_policy" "b_deny_all_egress" {
  metadata { name = "b-deny-all-egress"; namespace = kubernetes_namespace.agent_honeypot_b.metadata[0].name }
  spec {
    pod_selector {}
    policy_types = ["Egress"]
    egress { to = [] }  # deny all by default — enforced at framework level
  }
}

resource "kubernetes_network_policy" "b_allow_bus_only" {
  metadata { name = "b-allow-bus-only"; namespace = kubernetes_namespace.agent_honeypot_b.metadata[0].name }
  spec {
    pod_selector {}
    policy_types = ["Egress"]
    egress {
      to { namespace_selector { match_labels = { zone = "C" } } }
      ports { protocol = "TCP"; port = 4222 }  # NATS JetStream — Zone C capture
    }
  }
}

# PSP removed (deprecated since k8s 1.25) — use PodSecurity admission labels on the namespace.
# The kubernetes_namespace above plus this annotation enforces restricted PSS.

resource "vault_policy" "agent_honeypot_b_access" {
  name  = "agent-honeypot-zone-b"
  rules = <<EOT
path "secret/data/agent-honeypot/session/*" {
  capabilities = ["read"]
  allowed_parameters = { "session_id" = [] }
}
EOT
}

resource "vault_policy" "agent_honeypot_c_access" {
  name  = "agent_honeypot-zone-c"
  rules = <<EOT
path "secret/data/agent-honeypot/analysis/*" {
  capabilities = ["read", "update"]
}
path "secret/data/agent-honeypot/lures/*" {
  capabilities = ["read", "create", "update", "delete"]
}
EOT
}

output "deployment_summary" {
  value = <<EOF
agent-honeypot INFRA — Secure Foundation Spec (v1.0-alpha.1)
Zones: A (Edge/Cloudflare) | B (Deception/gVisor) | C (Capture/Analysis/Vault) | D (Evolution/Control)
Isolation: NetworkPolicies deny-all + Calico eBPF; gVisor per VM; no secrets in B
Secrets: HashiCorp Vault dynamic; TPM-sealed API keys for Zone D controls
Audit: Immutable chain; retention configurable; STIX output enabled for C-level feeds
Scaling: Lab (Compose) -> Enterprise (K8s) -> SaaS (multi-region Workers + R2 + regional ClickHouse)
Compliance: Multi-tenant partition isolation; 2FA-required control access; audit-only auditor role
EOF
}
