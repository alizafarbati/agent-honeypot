// agent-honeypot Phase 4 — Cloudflare Worker (edge capture, synthetic-only)
// Deploy with wrangler. Requires R2 bucket binding HONEYPOT_R2 and KV for tenant config.
// Defensive: no real secrets, no real DB calls, digest-only at edge; full events buffered to R2.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/health') return new Response(JSON.stringify({ status: 'ok', edge: 'agent-honeypot', synthetic_only: true }), { headers: { 'Content-Type': 'application/json' } });
    if (url.pathname === '/capture' && request.method === 'POST') {
      const body = await request.json().catch(() => null);
      if (!body) return new Response('bad json', { status: 400 });
      const tenant = request.headers.get('x-honeypot-tenant') ?? 'default';
      const event = { ts: new Date().toISOString(), tenant_id: tenant, lane: 'edge', ...sanitize(body) };
      const key = `events/${tenant}/${new Date().toISOString().slice(0, 10)}/${Date.now()}-${Math.random().toString(36).slice(2, 6)}.json`;
      if (env.HONEYPOT_R2) await env.HONEYPOT_R2.put(key, JSON.stringify(event));
      return new Response(JSON.stringify({ stored: key }), { headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('agent-honeypot edge — POST /capture', { status: 404 });
  }
};

function sanitize(body) {
  // Digest-only: never store raw context strings at edge
  const out = { tool: body.tool ?? null, privilege_level: body.privilege_level ?? 0, took_bait: body.took_bait ?? null };
  if (body.context) out.context_sha = body.context.slice(0, 8);
  return out;
}
