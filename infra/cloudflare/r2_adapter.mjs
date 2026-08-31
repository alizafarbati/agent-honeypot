// agent-honeypot Phase 4 — R2 adapter (local file fallback + R2 when env set)
// Lab: writes to infra/cloudflare/r2_local/*.json . Production: uses env.HONEYPOT_R2 binding.

import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const LOCAL_DIR = resolve(here, 'r2_local');
mkdirSync(LOCAL_DIR, { recursive: true });

export async function putObject(env, key, body) {
  if (env?.HONEYPOT_R2) return env.HONEYPOT_R2.put(key, body);
  const safe = key.replace(/[^a-zA-Z0-9._\-\/]/g, '_');
  writeFileSync(resolve(LOCAL_DIR, safe.replace(/\//g, '__')), typeof body === 'string' ? body : JSON.stringify(body));
  return { key: safe };
}
export async function listObjects(env, prefix) {
  if (env?.HONEYPOT_R2) { const l = await env.HONEYPOT_R2.list({ prefix }); return l.objects ?? []; }
  const { readdirSync } = await import('node:fs');
  return readdirSync(LOCAL_DIR).filter(f => f.startsWith(prefix.replace(/\//g, '__'))).map(f => ({ key: f }));
}
