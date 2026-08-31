// agent-honeypot Phase 9 — Secrets Rotation Schedule ()
// Declarative rotation policy for Vault dynamic secrets.

export const rotationPolicy = {
  // lab: file-based reminder; enterprise: Vault Agent auto-rotation
  schedules: [
    { secret: 'agent-honeypot/siem/token', every: '30d', action: 'vault rotate', owner: 'control/siem' },
    { secret: 'agent-honeypot/r2/edge_key', every: '90d', action: 'r2 key rotation', owner: 'infra/cloudflare' },
    { secret: 'agent-honeypot/tenant/*', every: '90d', action: 'tenant api_key_sha refresh', owner: 'control/tenant' },
  ],
  check() {
    return this.schedules.map(s => ({ ...s, next_due: `every ${s.every} from last rotation (track in Vault metadata)` }));
  }
};
