/* Deterministic replay math. No timers, network calls, or invented verdicts. */
(function (root) {
  "use strict";
  const verdicts = ["benign", "botnet", "ddos", "unknown"];
  const clamp = (x, min = 0, max = 1) => Math.max(min, Math.min(max, x));
  function connectionKey(value) {
    if (!value.source || !value.destination) return "";
    return JSON.stringify([value.protocol, ...[
      [normalizeIP(value.source), value.sport], [normalizeIP(value.destination), value.dport]
    ].sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))]);
  }
  function planDrops(packets, events) {
    const connections = new Map();
    const rateWindows = new Map();
    for (const event of events) {
      if (event.flow.response?.simulate !== "would_block" || !["botnet", "ddos"].includes(event.flow.prediction)
          || event.flow.confidence < .75 || event.flow.entropy > .8) continue;
      const key = connectionKey(event.flow);
      if (!connections.has(key)) connections.set(key, {plans: [], index: 0, active: null});
      connections.get(key).plans.push(event);
    }
    for (const packet of packets) {
      const state = connections.get(connectionKey(packet));
      if (!state) continue;
      while (state.index < state.plans.length && state.plans[state.index].progress <= packet.progress &&
          (state.plans[state.index].flow.ready_sequence == null || state.plans[state.index].flow.ready_sequence < packet.sequence)) {
        state.active = state.plans[state.index++];
      }
      // A new SYN starts a new session; a previous session's decision must
      // not suppress another connection that reuses the same tuple.
      if (packet.tcp_flags != null && (packet.tcp_flags & 0x12) === 2) state.active = null;
      const active = state.active;
      if (active && packet.timestamp > active.flow.ready_timestamp &&
          packet.timestamp <= active.flow.ready_timestamp + (active.flow.response.block_ttl_seconds || 30)) {
        packet.wouldDrop = true; packet.actionFlow = active.flow.id;
      } else if (active && packet.timestamp === active.flow.ready_timestamp && active.flow.ready_sequence != null && packet.sequence > active.flow.ready_sequence) {
        packet.wouldDrop = true; packet.actionFlow = active.flow.id;
      }
      if (packet.wouldDrop) {
        const bucket = `${connectionKey(packet)}:${active.flow.id}:${Math.floor(packet.timestamp - active.flow.ready_timestamp)}`;
        const count = (rateWindows.get(bucket) || 0) + 1; rateWindows.set(bucket, count);
        packet.wouldRateDrop = active.flow.response.rate_limit === "would_rate_limit" && count > (active.flow.response.rate_limit_packets_per_second || 5);
      }
    }
  }
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
    const packetRows = (result.packet_log?.rows || []).filter(row => !host ||
      (row[3] && normalizeIP(row[3]) === host) || (row[5] && normalizeIP(row[5]) === host));
    const records = result.packet_log ? packetRows.map(row => [row[1], row[2]]) :
      flows.flatMap(f => f.packet_timeline || Array.from({length: f.packets}, () => [f.timestamp, f.bytes / f.packets]));
    const original = !host && result.timeline;
    const start = original ? original.start : records.reduce((n,r) => Math.min(n,r[0]), Infinity);
    const packetEnd = records.reduce((n,r) => Math.max(n,r[0]), -Infinity);
    const end = original ? original.end : flows.reduce((n,f) => Math.max(n, f.ready_timestamp ?? f.timestamp), packetEnd);
    const progress = stamp => .02 + .96 * (end > start ? clamp((stamp - start) / (end - start)) : 0);
    const bins = (original ? original.bins : binsFor(records, start, end)).map((b, index) => ({...b, progress: progress(b.timestamp), index}));
    const events = flows.map(f => ({ flow: f, progress: progress(f.ready_timestamp ?? f.timestamp) }))
      .sort((a, b) => a.progress - b.progress || a.flow.id - b.flow.id);
    const packetEvents = packetRows.map(row => ({id: `packet-${row[0]}`, kind: "packet", timestamp: row[1], progress: progress(row[1]),
        sequence: row[0], bytes: row[2], source: row[3], sport: row[4], destination: row[5], dport: row[6], protocol: row[7], tcp_flags: row[9]}))
      .sort((a,b) => a.progress - b.progress || a.sequence - b.sequence);
    planDrops(packetEvents, events);
    const responseEvents = events.filter(e => e.flow.response && e.flow.prediction !== "benign").map(e => ({
      id: `response-${e.flow.id}`, kind: "action", flow: e.flow, progress: e.progress,
      timestamp: e.flow.ready_timestamp ?? e.flow.timestamp, response: e.flow.response
    }));
    const logEvents = [...packetEvents, ...events.filter(e => e.flow.prediction !== "benign").map(e => ({
      id: `flow-${e.flow.id}`, kind: e.flow.prediction === "unknown" ? "review" : "threat",
      timestamp: e.flow.ready_timestamp ?? e.flow.timestamp, progress: e.progress, flow: e.flow
    })), ...responseEvents].sort((a,b) => a.progress - b.progress || (a.kind === "packet" ? 0 : a.kind === "action" ? 2 : 1) - (b.kind === "packet" ? 0 : b.kind === "action" ? 2 : 1));
    return { bins, events, packetEvents, logEvents, start, end, focus: host || (virtual ? focus : ""),
      logAvailable: !!result.packet_log,
      scope: host && result.packet_log ? "All recorded packets for this host" : host || !original ? "Represented flow packets" : "All recorded packets",
      totalPackets: bins.reduce((n,b) => n + b.count, 0), result };
  }
  function snapshot(model, position, mode = "monitor") {
    const progress = clamp(position);
    const bins = model.bins.filter(b => b.progress <= progress);
    const events = model.events.filter(e => e.progress <= progress);
    const log = model.logEvents.filter(e => e.progress <= progress).map(e => e.kind === "action"
      ? {...e, action: mode === "simulate" ? e.response.simulate : mode === "rate_limit" ? e.response.rate_limit || "review" : e.response.monitor}
      : e.kind === "packet" ? {...e, disposition: (mode === "simulate" && e.wouldDrop) || (mode === "rate_limit" && e.wouldRateDrop) ? "would_drop" : "observed"} : e);
    const packets = model.logAvailable ? log.reduce((n,e) => n + (e.kind === "packet" ? 1 : 0), 0) : bins.reduce((n,b) => n + b.count, 0);
    const flows = events.map(e => e.flow);
    const counts = Object.fromEntries(verdicts.map(key => [key, 0]));
    flows.forEach(f => counts[f.prediction]++);
    const drops = log.filter(e => e.disposition === "would_drop").length;
    return { flows, counts, bins, log, packets, response: {mode, dropped: drops, forwarded: packets - drops,
      blockedFlows: log.filter(e => e.kind === "action" && e.action === "would_block").length,
      rateLimitedFlows: log.filter(e => e.kind === "action" && e.action === "would_rate_limit").length},
      bytes: model.logAvailable ? log.reduce((n,e) => n + (e.kind === "packet" ? e.bytes : 0), 0) : bins.reduce((n,b) => n + b.bytes, 0), represented: flows.reduce((n,f) => n + f.packets, 0),
      captureTimestamp: model.start + clamp((progress - .02) / .96) * (model.end - model.start) };
  }
  const api = { prepare, snapshot, normalizeIP, clamp };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.TrafficReplay = api;
})(typeof window !== "undefined" ? window : globalThis);
