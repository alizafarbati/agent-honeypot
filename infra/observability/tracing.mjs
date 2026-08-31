// agent-honeypot Phase 8 — Tracing (OpenTelemetry stub, )
// Lab: console span export. Enterprise: swap exporter to OTLP endpoint via OTEL_EXPORTER_OTLP_ENDPOINT.

export function startSpan(name, attrs = {}) {
  const start = Date.now();
  return {
    name, attrs, start,
    end(extra = {}) {
      const dur = Date.now() - start;
      const span = { name, duration_ms: dur, attrs: { ...attrs, ...extra }, ts: new Date().toISOString() };
      if (process.env.OTEL_EXPORTER_OTLP_ENDPOINT) {
        // Enterprise: OTLP export would happen here (fetch to collector)
        console.error(`[trace] ${name} ${dur}ms`, JSON.stringify(span.attrs).slice(0, 300));
      } else {
        console.error(`[trace:lab] ${name} ${dur}ms`);
      }
      return span;
    },
    setAttr(k, v) { attrs[k] = v; }
  };
}

export function withSpan(name, attrs, fn) {
  const span = startSpan(name, attrs);
  try { const r = fn(span); if (r && typeof r.then === 'function') return r.then(v => { span.end(); return v; }, e => { span.end({ error: String(e).slice(0,100) }); throw e; }); span.end(); return r; }
  catch (e) { span.end({ error: String(e).slice(0,100) }); throw e; }
}
