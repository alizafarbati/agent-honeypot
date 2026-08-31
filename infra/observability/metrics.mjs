// agent-honeypot Phase 8 — Metrics (Prometheus exposition, )
// Lab: in-memory counters exposed at /metrics. Enterprise: push to Prometheus via remote_write.

const counters = new Map();
const histograms = new Map();

export function inc(name, labels = {}, by = 1) {
  const k = `${name}{${Object.entries(labels).map(([kk,v])=>`${kk}="${v}"`).join(',')}}`;
  counters.set(k, (counters.get(k) ?? 0) + by);
}
export function observe(histName, value, labels = {}) {
  const k = `${histName}{${Object.entries(labels).map(([kk,v])=>`${kk}="${v}"`).join(',')}}`;
  const cur = histograms.get(k) ?? { sum: 0, count: 0, buckets: new Map() };
  cur.sum += value; cur.count += 1;
  // simple buckets
  for (const b of [50,100,250,500,1000,2500]) {
    if (value <= b) cur.buckets.set(b, (cur.buckets.get(b) ?? 0) + 1);
  }
  histograms.set(k, cur);
}

export function exposition() {
  let out = '';
  for (const [k, v] of counters) out += `# TYPE ${k.split('{')[0]} counter\n${k} ${v}\n`;
  for (const [k, h] of histograms) {
    out += `# TYPE ${k.split('{')[0]} histogram\n`;
    out += `${k}_sum ${h.sum}\n${k}_count ${h.count}\n`;
  }
  return out || '# no metrics yet\n';
}

export function metricsHandler(req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
  res.end(exposition());
}
