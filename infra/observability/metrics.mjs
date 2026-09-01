// agent-honeypot Phase 8 — Metrics (Prometheus exposition)
// Lab: in-memory counters exposed at /metrics. Enterprise: push to Prometheus via remote_write.
//
// v0.2.2 fix: histogram exposition previously emitted only _sum and _count.
// Prometheus text format REQUIRES cumulative _bucket{le="..."} lines plus
// le="+Inf" — without them real scrapers (Prometheus, Grafana agents) either
// reject the scrape or silently drop the histogram series.

const counters = new Map();
const histograms = new Map();
const BUCKETS = [50, 100, 250, 500, 1000, 2500];

function labelStr(labels = {}) {
  return Object.entries(labels).map(([k, v]) => `${kk(k)}="${vv(v)}"`).join(',');
}
// Keep original escaping behavior (raw interpolation) for back-compat;
// quote values defensively.
const kk = (k) => String(k).replace(/"/g, "'");
const vv = (v) => String(v).replace(/"/g, "'");

export function inc(name, labels = {}, by = 1) {
  const k = `${name}{${labelStr(labels)}}`;
  counters.set(k, (counters.get(k) ?? 0) + by);
}
export function observe(histName, value, labels = {}) {
  const k = `${histName}{${labelStr(labels)}}`;
  const cur = histograms.get(k) ?? { sum: 0, count: 0, buckets: new Map(BUCKETS.map(b => [b, 0])) };
  cur.sum += value; cur.count += 1;
  // cumulative buckets: every boundary >= value increments
  for (const b of BUCKETS) if (value <= b) cur.buckets.set(b, (cur.buckets.get(b) ?? 0) + 1);
  histograms.set(k, cur);
}

export function exposition() {
  let out = '';
  const seenTypes = new Set();
  for (const [k, v] of counters) {
    const base = k.split('{')[0];
    if (!seenTypes.has(`c:${base}`)) { out += `# TYPE ${base} counter\n`; seenTypes.add(`c:${base}`); }
    out += `${k} ${v}\n`;
  }
  for (const [k, h] of histograms) {
    const base = k.split('{')[0];
    if (!seenTypes.has(`h:${base}`)) { out += `# TYPE ${base} histogram\n`; seenTypes.add(`h:${base}`); }
    // cumulative buckets with le labels, then +Inf, then sum/count
    for (const b of BUCKETS) out += `${k.replace(/\}$/, `,le="${b}"`)} ${h.buckets.get(b) ?? 0}\n`;
    out += `${k.replace(/\}$/, ',le="+Inf"')} ${h.count}\n`;
    out += `${k.replace(/\}$/, '_sum')} ${h.sum}\n`;
    out += `${k.replace(/\}$/, '_count')} ${h.count}\n`;
  }
  return out || '# no metrics yet\n';
}

export function metricsHandler(req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
  res.end(exposition());
}
