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
      const event = { ts: new Date().toISOString(), tenant_id: tenant, lane: 'edge', ...await sanitize(body) };
      const key = `events/${tenant}/${new Date().toISOString().slice(0, 10)}/${Date.now()}-${crypto.randomUUID().slice(0, 8)}.json`;
      if (env.HONEYPOT_R2) await env.HONEYPOT_R2.put(key, JSON.stringify(event));
      return new Response(JSON.stringify({ stored: key }), { headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('agent-honeypot edge — POST /capture', { status: 404 });
  }
};

function sanitize(body) {
  // Digest-only: never store raw context at the edge (v0.2.2 — this previously
  // stored an 8-char raw prefix, leaking plaintext attacker context to R2).
  // Full SHA-256 via WebCrypto (Workers runtime has crypto.subtle, not node:crypto).
  const out = { tool: body.tool ?? null, privilege_level: body.privilege_level ?? 0, took_bait: body.took_bait ?? null };
  if (typeof body.context === 'string' && body.context.length > 0) {
    // SHA-256 is async; sanitize is invoked from the async fetch handler, so
    // callers must await. Kept as a promise-preserving helper below.
    out.context_sha_promise = crypto.subtle.digest('SHA-256', new TextEncoder().encode(body.context)).then(buf => {
      out.context_sha = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
      delete out.context_sha_promise;
      return out.context_sha;
    });
  }
  return out;
}
