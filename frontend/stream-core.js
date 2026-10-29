/* Deterministic replay math. No timers, network calls, or invented verdicts. */
(function (root) {
  "use strict";
  const verdicts = ["benign", "botnet", "ddos", "unknown"];
  const clamp = (x, min = 0, max = 1) => Math.max(min, Math.min(max, x));
  function normalizeIP(value) {
    const text = String(value).trim().toLowerCase().replace(/^\[|\]$/g, "");
    if (/^\d+\.\d+\.\d+\.\d+$/.test(text)) {
      const fields = text.split(".");
      if (fields.every(v => Number(v) <= 255 && String(Number(v)) === v)) return text;
    }
    if (text.includes(":")) {
      try { return new URL(`http://[${text}]/`).hostname.replace(/^\[|\]$/g, ""); } catch { /* invalid IPv6 */ }
    }
    throw new Error("Enter a valid IPv4 or IPv6 address.");
  }
  function binsFor(records, start, end) {
    const bins = new Map();
    for (const [stamp, size] of records) {
      const index = Math.min(511, Math.floor((stamp - start) / Math.max(end - start, 1e-9) * 512));
      const bin = bins.get(index) || { timestamp: stamp, count: 0, bytes: 0 };
      bin.timestamp = Math.max(bin.timestamp, stamp); bin.count++; bin.bytes += size;
      bins.set(index, bin);
    }
    return [...bins.values()].sort((a, b) => a.timestamp - b.timestamp);
  }
  function prepare(result, focus = "") {
    const virtual = result.simulation?.address === focus;
    const host = focus && !virtual ? normalizeIP(focus) : "";
    const flows = result.flows.filter(f => !host || normalizeIP(f.source) === host || normalizeIP(f.destination) === host);
    if (!flows.length) throw new Error("This IP has no supported flows in the selected capture.");
    const records = flows.flatMap(f => f.packet_timeline || Array.from({length: f.packets}, () => [f.timestamp, f.bytes / f.packets]));
    const original = !host && result.timeline;
    const start = original ? original.start : records.reduce((n,r) => Math.min(n,r[0]), Infinity);
    const packetEnd = records.reduce((n,r) => Math.max(n,r[0]), -Infinity);
    const end = original ? original.end : flows.reduce((n,f) => Math.max(n, f.ready_timestamp ?? f.timestamp), packetEnd);
    const progress = stamp => .02 + .96 * (end > start ? clamp((stamp - start) / (end - start)) : 0);
    const bins = (original ? original.bins : binsFor(records, start, end)).map((b, index) => ({...b, progress: progress(b.timestamp), index}));
    const events = flows.map(f => ({ flow: f, progress: progress(f.ready_timestamp ?? f.timestamp) }))
      .sort((a, b) => a.progress - b.progress || a.flow.id - b.flow.id);
    return { bins, events, start, end, focus: host || (virtual ? focus : ""),
      scope: host || !original ? "Represented flow packets" : "All recorded packets",
      totalPackets: bins.reduce((n,b) => n + b.count, 0), result };
  }
  function snapshot(model, position) {
    const progress = clamp(position);
    const bins = model.bins.filter(b => b.progress <= progress);
    const events = model.events.filter(e => e.progress <= progress);
    const flows = events.map(e => e.flow);
    const counts = Object.fromEntries(verdicts.map(key => [key, 0]));
    flows.forEach(f => counts[f.prediction]++);
    return { flows, counts, bins, packets: bins.reduce((n,b) => n + b.count, 0),
      bytes: bins.reduce((n,b) => n + b.bytes, 0), represented: flows.reduce((n,f) => n + f.packets, 0),
      captureTimestamp: model.start + clamp((progress - .02) / .96) * (model.end - model.start) };
  }
  const api = { prepare, snapshot, normalizeIP, clamp };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.TrafficReplay = api;
})(typeof window !== "undefined" ? window : globalThis);
