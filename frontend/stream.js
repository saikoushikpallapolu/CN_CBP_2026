"use strict";
class TrafficStream {
  constructor(onFrame, onInspect) {
    this.canvas = document.getElementById("traffic-wave");
    this.ctx = this.canvas.getContext("2d");
    this.onFrame = onFrame; this.onInspect = onInspect;
    this.model = null; this.position = 0; this.playing = false; this.speed = 1;
    this.duration = 30; this.lastFrame = 0; this.lastUpdate = 0; this.hitTargets = [];
    this.reduced = matchMedia("(prefers-reduced-motion: reduce)");
    this.observer = new ResizeObserver(() => this.draw(performance.now()));
    this.observer.observe(this.canvas);
    document.getElementById("stream-play").addEventListener("click", () => this.toggle());
    document.getElementById("stream-restart").addEventListener("click", () => this.seek(0, true));
    document.getElementById("stream-speed").addEventListener("change", e => { this.speed = Number(e.target.value); });
    document.getElementById("stream-seek").addEventListener("input", e => this.seek(Number(e.target.value) / 1000));
    this.canvas.addEventListener("click", e => {
      const box = this.canvas.getBoundingClientRect();
      const x = e.clientX - box.left, y = e.clientY - box.top;
      const hit = this.hitTargets.find(p => Math.hypot(p.x - x, p.y - y) < 18);
      if (hit) this.onInspect(hit.flow);
    });
    document.addEventListener("visibilitychange", () => {
      // No silent fast-forward when a background tab returns.
      if (document.hidden && this.playing) this.toggle();
    });
    this.draw(0);
  }
  load(result, focus = "", {autoplay = !this.reduced.matches} = {}) {
    const next = TrafficReplay.prepare(result, focus);
    this.stop(); this.model = next; this.position = 0;
    document.getElementById("stream-source").textContent = focus ? `${focus} · ${result.filename}` : result.filename;
    document.getElementById("stream-mode").textContent = result.simulation ? "VIRTUAL SENSOR" : "CAPTURE REPLAY";
    document.getElementById("stream-empty").hidden = true;
    document.getElementById("stream-note").textContent = `${next.scope}. ${result.simulation ? "Retimed public samples; no network traffic sent." : result.timeline ? "Original capture timing fitted to 30 seconds." : "Legacy flow-context replay; full packet timing unavailable."} Verdicts are computed before playback. Loop repeats the same samples.`;
    document.getElementById("stream-play").disabled = false;
    document.getElementById("stream-restart").disabled = false;
    document.getElementById("stream-seek").disabled = false;
    this.publish(); this.draw(0);
    // An explicit Connect/Play action may start playback even with reduced
    // motion enabled; decorative pulses still respect that preference.
    if (autoplay) this.toggle();
    this.publish();
  }
  clear() {
    this.stop(); this.model = null; this.position = 0;
    document.getElementById("stream-empty").hidden = false;
    document.getElementById("stream-source").textContent = "Connect the virtual sensor or open a capture";
    document.getElementById("stream-mode").textContent = "READY TO REPLAY";
    for (const id of ["stream-play", "stream-restart", "stream-seek"]) document.getElementById(id).disabled = true;
    document.getElementById("stream-seek").value = 0;
    document.getElementById("stream-position").textContent = "0.0 / 30 s";
    document.getElementById("stream-clock").textContent = "— UTC";
    document.getElementById("stream-state").textContent = "Waiting";
    document.getElementById("stream-announcement").textContent = "";
    this.draw(0);
  }
  stop() {
    cancelAnimationFrame(this.request); this.playing = false; this.lastFrame = 0;
    document.getElementById("stream-play").textContent = "▶ Play";
  }
  toggle() {
    if (!this.model) return;
    if (this.playing) { this.stop(); this.publish(); this.draw(performance.now()); return; }
    if (this.position >= 1) this.position = 0;
    this.playing = true; this.lastFrame = 0;
    document.getElementById("stream-play").textContent = "Ⅱ Pause";
    this.request = requestAnimationFrame(t => this.tick(t));
  }
  seek(value, play = false) {
    if (!this.model) return;
    this.position = TrafficReplay.clamp(value); this.lastFrame = 0;
    this.publish(); this.draw(performance.now());
    if (play && !this.playing) this.toggle();
  }
  tick(time) {
    if (!this.playing) return;
    if (this.lastFrame) this.position = Math.min(1, this.position + Math.min(.1, (time - this.lastFrame) / 1000) * this.speed / this.duration);
    this.lastFrame = time;
    if (time - this.lastUpdate >= 120 || this.position >= 1) { this.publish(); this.lastUpdate = time; }
    this.draw(time);
    if (this.position >= 1 && document.getElementById("stream-loop").checked) {
      this.position = 0; this.lastFrame = 0; this.publish();
      this.request = requestAnimationFrame(t => this.tick(t));
    }
    else if (this.position >= 1) { this.stop(); this.publish(); this.draw(time); }
    else this.request = requestAnimationFrame(t => this.tick(t));
  }
  publish() {
    if (!this.model) return;
    const frame = TrafficReplay.snapshot(this.model, this.position);
    document.getElementById("stream-seek").value = Math.round(this.position * 1000);
    document.getElementById("stream-position").textContent = `${(this.position * this.duration).toFixed(1)} / 30 s`;
    const date = new Date(frame.captureTimestamp * 1000);
    document.getElementById("stream-clock").textContent = date.toISOString().slice(11, 23) + " UTC";
    document.getElementById("stream-state").textContent = this.position >= 1 ? "Replay complete" : this.playing ? "Replaying" : "Paused";
    this.onFrame(frame, this.model, this.position);
  }
  draw(time) {
    const box = this.canvas.getBoundingClientRect();
    const w = box.width, h = box.height;
    if (!w || !h) return;
    const ratio = Math.min(devicePixelRatio || 1, 2);
    if (this.canvas.width !== Math.round(w * ratio) || this.canvas.height !== Math.round(h * ratio)) {
      this.canvas.width = Math.round(w * ratio); this.canvas.height = Math.round(h * ratio);
    }
    const ctx = this.ctx; ctx.setTransform(ratio, 0, 0, ratio, 0, 0); ctx.clearRect(0, 0, w, h);
    const base = h * .5, head = w * .82, window = .23;
    const toX = p => head - (this.position - p) / window * w;
    const maxCount = this.model ? Math.max(1, ...this.model.bins.map(b => b.count)) : 1;
    const bins = this.model?.bins.filter(b => toX(b.progress) >= -20 && toX(b.progress) <= w + 20) || [];
    const levels = new Float32Array(Math.ceil(w / 6) + 1);
    for (const b of bins) {
      const center = toX(b.progress);
      for (let j = Math.max(0, Math.floor((center - 36) / 6)); j <= Math.min(levels.length - 1, Math.ceil((center + 36) / 6)); j++)
        levels[j] = Math.max(levels[j], Math.max(0, 1 - Math.abs(j * 6 - center) / 36) * Math.log1p(b.count) / Math.log1p(maxCount));
    }
    const activity = x => levels[Math.min(levels.length - 1, Math.floor(x / 6))] || 0;
    const waveY = x => base + Math.sin(x * .026 - this.position * 19) * (8 + activity(x) * 49) + Math.sin(x * .011 + this.position * 11) * 10;
    ctx.strokeStyle = "#203345"; ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 64) { ctx.beginPath(); ctx.moveTo(x, 20); ctx.lineTo(x, h - 20); ctx.stroke(); }
    for (let y = 30; y < h; y += 50) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
    ctx.beginPath(); ctx.moveTo(0, base);
    for (let x = 0; x <= w; x += 3) ctx.lineTo(x, waveY(x));
    ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
    const fill = ctx.createLinearGradient(0, base - 50, 0, h); fill.addColorStop(0, "#36d1b529"); fill.addColorStop(1, "#36d1b500");
    ctx.fillStyle = fill; ctx.fill();
    for (const [width, alpha] of [[10, .055], [5, .12], [1.8, .9]]) {
      ctx.beginPath(); for (let x = 0; x <= w; x += 3) x ? ctx.lineTo(x, waveY(x)) : ctx.moveTo(x, waveY(x));
      ctx.strokeStyle = `rgba(77,219,192,${alpha})`; ctx.lineWidth = width; ctx.stroke();
    }
    const palette = { benign: "#4ddbc0", botnet: "#f7bc57", ddos: "#ff697b", unknown: "#9cacc3" };
    for (const bin of bins) {
      const x = toX(bin.progress), y = waveY(x); const observed = bin.progress <= this.position;
      ctx.globalAlpha = observed ? .85 : .17;
      ctx.fillStyle = observed ? palette.benign : "#b6cad7";
      ctx.beginPath(); ctx.arc(x, y, 2 + Math.min(5, Math.log2(bin.count + 1)), 0, Math.PI * 2); ctx.fill();
    }
    ctx.globalAlpha = 1; this.hitTargets = [];
    const events = this.model?.events.filter(e => e.progress <= this.position && e.flow.prediction !== "benign" && toX(e.progress) > -25) || [];
    for (const event of events.slice(-90)) {
      const x = toX(event.progress), y = waveY(x), color = palette[event.flow.prediction];
      const age = (this.position - event.progress) * this.duration;
      ctx.fillStyle = color; ctx.strokeStyle = color; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(x, y, 5, 0, Math.PI * 2); ctx.fill();
      const radius = 9 + (this.playing && !this.reduced.matches ? (age * 22) % 30 : 4);
      ctx.globalAlpha = .7 * (1 - (radius - 9) / 35);
      ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2); ctx.stroke(); ctx.globalAlpha = 1;
      this.hitTargets.push({x, y, flow: event.flow});
    }
    ctx.setLineDash([3, 6]); ctx.strokeStyle = "#aec7d85e"; ctx.beginPath(); ctx.moveTo(head, 14); ctx.lineTo(head, h - 14); ctx.stroke(); ctx.setLineDash([]);
    ctx.fillStyle = "#8da8bb"; ctx.font = "10px Segoe UI, sans-serif";
    ctx.fillText("PACKET ACTIVITY", 18, 23); ctx.fillText("NOW", head - 10, h - 12);
  }
}
window.TrafficStream = TrafficStream;
