"use strict";
const $ = (id) => document.getElementById(id);
const state = {
  result: null,
  selected: null,
  health: null,
  page: 0,
  busy: false,
  key: sessionStorage.getItem("traffic-key") || "",
  demo: null,
};
const colors = {
  benign: "#0a957a",
  botnet: "#bc8427",
  ddos: "#dc5263",
  unknown: "#93a3b8",
};
const labels = {
  benign: "Benign",
  botnet: "Botnet",
  ddos: "DDoS",
  unknown: "Unknown",
};
const number = (value) => new Intl.NumberFormat().format(value);
const endpointText = (address, port) =>
  `${address.includes(":") ? `[${address}]` : address}:${port}`;
function node(tag, text, className) {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (className) n.className = className;
  return n;
}
function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").classList.toggle("error", error);
  $("notice").hidden = !message;
}
async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.key) headers["X-API-Key"] = state.key;
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let message;
    try {
      message = (await response.json()).detail;
    } catch {
      message = response.statusText;
    }
    if (response.status === 401) $("auth-dialog").showModal();
    throw new Error(
      typeof message === "string"
        ? message
        : `Request failed (${response.status})`,
    );
  }
  return response.json();
}
function badge(value) {
  return node("span", labels[value] || value, `badge ${value}`);
}
function kv(label, value) {
  const row = node("div", undefined, "key-value");
  row.append(node("span", label), node("span", String(value ?? "Unavailable")));
  return row;
}
function download(value, name, type = "application/json") {
  const blob = new Blob(
    [typeof value === "string" ? value : JSON.stringify(value, null, 2)],
    { type },
  );
  const url = URL.createObjectURL(blob);
  const a = node("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function setBusy(busy) {
  state.busy = busy;
  $("dropzone").classList.toggle("loading", busy);
  $("samples").disabled = busy;
  $("file").disabled = busy;
  $("new").disabled = busy;
  $("queue").hidden = !busy;
}
async function refresh() {
  try {
    const health = await api("/api/health");
    state.health = health;
    $("engine-label").textContent =
      health.status === "online"
        ? health.production_ready
          ? "Validated model"
          : "Experimental model"
        : "Evidence mode";
    $("engine-dot").classList.toggle("online", health.production_ready);
    const runtimeName = { pytorch: "PyTorch", tensorrt: "TensorRT", onnxruntime: "ONNX Runtime" }[health.backend] || "Flow engine";
    $("engine-device").textContent = `${health.device?.includes("cuda") ? "GPU" : "CPU"} · ${runtimeName}`;
    $("upload-limit").textContent =
      `PCAP, PCAPNG · up to ${health.max_upload_mb} MB · multiple files supported`;
    if (!health.production_ready)
      notice(
        health.error ||
          "Model validation is incomplete. Review deployment gates before operational use.",
      );
    else notice("");
    const samples = await api("/api/samples");
    $("samples").replaceChildren(node("option", "Try a reference capture ↗"));
    $("samples").firstChild.value = "";
    for (const sample of samples) {
      const option = node(
        "option",
        sample.label + (sample.available ? "" : " · unavailable"),
      );
      option.value = sample.id;
      option.disabled = !sample.available;
      $("samples").append(option);
    }
    renderModel();
  } catch (error) {
    notice(error.message, true);
  }
}
function reset() {
  state.result = null;
  state.page = 0;
  state.selected = null;
  for (const id of [
    "metric-packets",
    "metric-flows",
    "metric-threats",
    "metric-time",
  ])
    $(id).textContent = "—";
  $("capture-name").textContent = "No capture selected";
  $("metric-coverage").textContent = "Awaiting capture";
  $("metric-speed").textContent = "End-to-end processing";
  $("metric-unknown").textContent = "Unknown traffic is escalated";
  $("export").disabled = true;
  $("csv").disabled = true;
  $("search").value = "";
  $("verdict").value = "";
  $("protocol").value = "";
  renderDistribution();
  renderFlows();
}
function showResult(result) {
  $("score-heading").textContent = result.model?.production_ready
    ? "CONFIDENCE"
    : "MODEL SCORE";
  notice(
    result.model?.production_ready
      ? ""
      : result.model_available
        ? "Experimental model · deployment gates have not passed."
        : "Evidence mode · trained model unavailable.",
  );
  state.result = result;
  state.page = 0;
  const t = result.telemetry;
  $("metric-packets").textContent = number(t.packet_count);
  $("metric-flows").textContent = number(t.flow_count);
  $("metric-threats").textContent = number(
    result.counts.botnet + result.counts.ddos,
  );
  $("metric-time").textContent =
    t.analysis_ms < 1000
      ? `${t.analysis_ms} ms`
      : `${(t.analysis_ms / 1000).toFixed(2)} s`;
  $("metric-coverage").textContent =
    `${number(result.coverage.analyzed_ip_packets)} packets fingerprinted`;
  $("metric-unknown").textContent =
    `${number(result.counts.unknown)} unknown · review required`;
  $("metric-speed").textContent =
    `${number(t.packets_per_second)} packets/s · observed`;
  $("capture-name").textContent = result.filename;
  $("export").disabled = false;
  $("csv").disabled = false;
  $("calibration-note").textContent =
    result.model?.verdict_policy === "release_gated" &&
    !result.model?.production_ready
      ? "Release gates failed · model scores only"
      : result.calibrated
        ? "Temperature calibrated · confidence ≥ 75% required"
        : result.model_available
          ? "Experimental model scores · calibration not validated"
          : "Evidence only · trained model unavailable";
  $("search").value = "";
  $("verdict").value = "";
  $("protocol").value = "";
  renderDistribution();
  renderFlows();
}
function renderDistribution() {
  const counts = state.result?.counts || {
    benign: 0,
    botnet: 0,
    ddos: 0,
    unknown: 0,
  };
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  $("donut-total").textContent = number(total);
  $("legend").replaceChildren();
  let position = 0;
  const segments = [];
  for (const [name, count] of Object.entries(counts)) {
    const row = node("div", undefined, "legend-line");
    row.append(
      node("i", undefined, `${name}-dot`),
      node("span", labels[name]),
      node("b", number(count)),
    );
    $("legend").append(row);
    const end = position + (total ? (count / total) * 100 : 0);
    segments.push(`${colors[name]} ${position}% ${end}%`);
    position = end;
  }
  $("donut").style.background = total
    ? `conic-gradient(${segments.join(",")})`
    : "#e9eef3";
}
function filteredFlows() {
  const query = $("search").value.toLowerCase().trim();
  const verdict = $("verdict").value;
  const protocol = $("protocol").value;
  const sort = $("sort").value;
  return [...(state.result?.flows || [])]
    .filter(
      (flow) =>
        (!verdict || flow.prediction === verdict) &&
        (!protocol || flow.protocol === protocol) &&
        (!query ||
          [
            flow.source,
            flow.destination,
            flow.sport,
            flow.dport,
            flow.protocol,
            flow.prediction,
          ]
            .join(" ")
            .toLowerCase()
            .includes(query)),
    )
    .sort((a, b) => (sort === "id" ? a.id - b.id : b[sort] - a[sort]));
}
function renderFlows() {
  const flows = filteredFlows();
  const pages = Math.ceil(flows.length / 25);
  state.page = Math.max(0, Math.min(state.page, pages - 1));
  $("flow-count").textContent = number(flows.length);
  $("flows").replaceChildren();
  $("empty").hidden = flows.length > 0;
  if (!flows.length) {
    $("empty").querySelector("h3").textContent = state.result
      ? "No flows match your filters"
      : "Your next investigation starts here";
    $("empty").querySelector("p").textContent = state.result
      ? "Adjust the verdict, protocol or search query."
      : "Upload a capture to explore flows, verdicts and byte fingerprints.";
  }
  for (const flow of flows.slice(state.page * 25, state.page * 25 + 25)) {
    const row = node("tr", undefined, "flow-row");
    const verdict = node("td");
    verdict.append(badge(flow.prediction));
    const endpoint = node("td", undefined, "endpoint");
    endpoint.append(
      node("span", endpointText(flow.source, flow.sport)),
      node("small", " → "),
      node("span", endpointText(flow.destination, flow.dport)),
    );
    const confidence = node(
      "td",
      state.result.model_available
        ? `${(flow.confidence * 100).toFixed(1)}%`
        : "—",
    );
    const inspect = node("td");
    const button = node("button", "↗", "flow-open");
    button.setAttribute("aria-label", `Inspect flow ${flow.id}`);
    button.addEventListener("click", () => inspectFlow(flow));
    inspect.append(button);
    row.append(
      verdict,
      endpoint,
      node("td", flow.protocol),
      node("td", String(flow.packets)),
      confidence,
      inspect,
    );
    $("flows").append(row);
  }
  $("page-label").textContent = flows.length
    ? `${number(state.page * 25 + 1)}–${number(Math.min(flows.length, state.page * 25 + 25))} of ${number(flows.length)} flow bursts`
    : "No flow evidence";
  $("prev").disabled = state.page === 0;
  $("next").disabled = state.page + 1 >= pages;
}
function inspectFlow(flow) {
  state.selected = flow;
  $("detail-title").textContent = `Flow ${String(flow.id).padStart(4, "0")}`;
  $("detail-summary").replaceChildren(badge(flow.prediction));
  $("detail-summary").append(
    node(
      "div",
      `${endpointText(flow.source, flow.sport)} → ${endpointText(flow.destination, flow.dport)}`,
      "detail-endpoints",
    ),
    kv("Protocol / packets", `${flow.protocol} / ${flow.packets}`),
    kv("Capture time", new Date(flow.timestamp * 1000).toISOString()),
    kv(
      "Normalized prediction entropy",
      state.result.model_available
        ? flow.entropy.toFixed(3)
        : "Model unavailable",
    ),
  );
  const ctx = $("fingerprint").getContext("2d");
  flow.fingerprint.forEach((byte, index) => {
    ctx.fillStyle = `rgb(${byte},${byte},${byte})`;
    ctx.fillRect((index % 32) * 10, Math.floor(index / 32) * 10, 10, 10);
  });
  $("probabilities").replaceChildren();
  for (const [name, value] of Object.entries(flow.probabilities)) {
    const row = node("div", undefined, "probability");
    const progress = node("progress");
    progress.max = 1;
    progress.value = value;
    progress.setAttribute("aria-label", `${name} probability`);
    row.append(
      node("span", labels[name]),
      progress,
      node(
        "span",
        state.result.model_available ? `${(value * 100).toFixed(1)}%` : "—",
      ),
    );
    $("probabilities").append(row);
  }
  $("hex").textContent = flow.hex_dump.join("\n");
  $("detail").showModal();
}
async function uploadFiles(files) {
  if (state.busy) return;
  const selected = [...files];
  if (!selected.length) return;
  setBusy(true);
  for (let i = 0; i < selected.length; i++) {
    const file = selected[i];
    $("queue").textContent =
      `Analyzing ${i + 1} / ${selected.length} · ${file.name}`;
    try {
      if (file.size > (state.health?.max_upload_mb || 64) * 1024 ** 2)
        throw new Error("Capture exceeds upload limit");
      const form = new FormData();
      form.append("file", file);
      const result = await api("/api/analyze/upload", {
        method: "POST",
        body: form,
      });
      showResult(result);
    } catch (error) {
      notice(`${file.name}: ${error.message}`, true);
    }
  }
  setBusy(false);
  $("file").value = "";
}
async function history() {
  const host = $("history");
  host.replaceChildren();
  try {
    const items = await api("/api/investigations");
    if (!items.length)
      host.append(
        node(
          "div",
          "No saved investigations yet. Analyze a capture to get started.",
          "info-card",
        ),
      );
    for (const item of items) {
      const card = node("article", undefined, "info-card");
      card.append(
        badge(item.prediction),
        node("h2", item.filename),
        kv("Analyzed", new Date(item.created_at).toLocaleString()),
        kv("Packets", number(item.telemetry.packet_count)),
        kv("Flow bursts", number(item.telemetry.flow_count)),
      );
      const button = node("button", "Open investigation ↗", "button secondary");
      button.addEventListener("click", async () => {
        try {
          showResult(await api(`/api/investigations/${item.id}`));
          switchView("investigate");
        } catch (error) {
          notice(error.message, true);
        }
      });
      card.append(button);
      host.append(card);
    }
  } catch (error) {
    notice(error.message, true);
  }
}
async function corpus() {
  const host = $("corpus");
  host.replaceChildren();
  try {
    const sources = await api("/api/data");
    if (!Object.keys(sources).length)
      host.append(
        node("div", "No external captures acquired yet.", "info-card"),
      );
    for (const [name, source] of Object.entries(sources)) {
      const card = node("article", undefined, "info-card");
      card.append(
        node("h2", name.toUpperCase()),
        kv("Status", source.status || "Acquisition failed"),
        kv(
          "Packets",
          source.capture?.packets ? number(source.capture.packets) : "—",
        ),
        kv(
          "Label source",
          source.labels
            ? "Flow intervals"
            : source.status?.startsWith("verified_normal")
              ? "Controlled normal capture"
              : source.status === "schedule_labeled_subset"
                ? "Schedule + endpoints"
                : "Unknown / pending",
        ),
      );
      if (source.capture?.sha256)
        card.append(node("p", `SHA-256: ${source.capture.sha256}`));
      if (source.error) card.append(node("p", source.error));
      host.append(card);
    }
  } catch (error) {
    notice(error.message, true);
  }
}
function renderModel() {
  const host = $("model");
  host.replaceChildren();
  if (!state.health) return;
  const h = state.health;
  const card = node("article", undefined, "info-card");
  card.append(
    node("h2", "Analysis engine"),
    kv("Architecture", h.model),
    kv("Runtime", `${h.backend} / ${h.device}`),
    kv("Representation", h.representation),
    kv("Checkpoint", h.checkpoint),
    kv("Production sign-off", h.production_ready ? "Passed" : "Not passed"),
  );
  if (h.error) card.append(node("p", h.error));
  host.append(card);
  const metrics = node("article", undefined, "info-card");
  metrics.append(node("h2", h.runtime_report ? "TensorRT evaluation" : "Independent-source evaluation"));
  const r = h.report || {};
  const measured = h.runtime_report
    ? { ...h.runtime_report, batch64_p95_ms: h.runtime_report.timings?.tensorrt?.batch64_p95_ms,
        temperature: h.runtime_report.engine_metadata?.temperature }
    : r;
  for (const [label, key] of [
    ["Flow accuracy", "accuracy"],
    ["Represented packet accuracy", "packet_weighted_accuracy"],
    ["Macro F1", "macro_f1"],
    ["Benign packets escalated", "benign_packet_escalation_rate"],
    ["Calibration error", "expected_calibration_error"],
    [`${h.runtime_report ? "GPU" : "PyTorch"} p95 / 64 flows (ms)`, "batch64_p95_ms"],
    ["Temperature", "temperature"],
  ])
    metrics.append(
      kv(
        label,
        measured[key] == null
          ? "Not measured"
          : key.includes("accuracy") || key.includes("rate")
            ? `${(Number(measured[key]) * 100).toFixed(2)}%`
            : Number(measured[key]).toFixed(4),
      ),
    );
  host.append(metrics);
  const gates = node("article", undefined, "info-card");
  gates.append(node("h2", "Deployment gates"));
  const requirements = r.gates || {
    accuracy: false,
    macro_f1: false,
    benign_fpr: false,
    latency: false,
    class_coverage: false,
    identity_invariance: false,
    stability_24h: false,
    independent_enterprise_audit: false,
  };
  for (const [name, passed] of Object.entries(requirements)) {
    const row = kv(
      name.replaceAll("_", " "),
      passed ? "Passed" : "Pending / not passed",
    );
    row.lastChild.className = passed ? "gate-pass" : "gate-fail";
    gates.append(row);
  }
  host.append(gates);
}
function switchView(name) {
  for (const view of document.querySelectorAll(".view"))
    view.hidden = view.id !== `view-${name}`;
  for (const nav of document.querySelectorAll(".nav"))
    nav.classList.toggle("active", nav.dataset.view === name);
  $("crumb").textContent = {
    investigate: "Investigations",
    history: "Capture history",
    corpus: "Data sources",
    model: "Model & validation",
    demo: "Test & demo",
  }[name];
  if (name === "history") history();
  if (name === "corpus") corpus();
  if (name === "model") renderModel();
}
for (const nav of document.querySelectorAll(".nav"))
  nav.addEventListener("click", () => switchView(nav.dataset.view));
$("run-demo").addEventListener("click", async () => {
  const button = $("run-demo");
  button.disabled = true;
  button.textContent = "Running real inference…";
  try {
    const report = await api("/api/demo", { method: "POST" });
    state.demo = report;
    $("demo-results").replaceChildren();
    for (const item of report.cases) {
      const card = node("article", undefined, "info-card");
      const pct = (value) => `${(value * 100).toFixed(1)}%`;
      card.append(node("h2", item.title), kv("Recorded truth", labels[item.expected_class]),
        kv("Capture group", item.source_group),
        kv("Flows", item.flow_count), kv("Correct class", pct(item.class_match_rate)),
        kv("Unknown / review", pct(item.unknown_rate)));
      if (item.expected_class === "benign") {
        card.append(kv("False attack alerts", pct(item.benign_attack_alert_rate)),
          kv("Total review rate", pct(item.benign_review_rate)));
      } else card.append(kv("Attack escalation", pct(item.attack_escalation_rate)));
      card.append(kv("Analysis time", `${item.analysis_ms} ms`));
      if (item.id === "demo-ddos") card.append(node("p", "Training-source reference; not an independent accuracy test."));
      const inspect = node("button", "Inspect capture ↗", "button secondary");
      inspect.addEventListener("click", async () => {
        if (state.busy) return;
        setBusy(true);
        try {
          showResult(await api("/api/analyze/sample", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sample_id: item.id }) }));
          switchView("investigate");
        } catch (error) { notice(error.message, true); }
        finally { setBusy(false); }
      });
      card.append(inspect);
      $("demo-results").append(card);
    }
    const exportCard = node("article", undefined, "info-card");
    exportCard.append(node("h2", "Evidence"), node("p", report.scope));
    const exportButton = node("button", "↓ Export demo report", "button secondary");
    exportButton.addEventListener("click", () => download(report, "trafficscan-demo.json"));
    exportCard.append(exportButton);
    $("demo-results").append(exportCard);
  } catch (error) { notice(error.message, true); }
  finally { button.disabled = false; button.textContent = "▷ Run demo suite"; }
});
$("file").addEventListener("change", (event) =>
  uploadFiles(event.target.files),
);
for (const event of ["dragenter", "dragover"])
  $("dropzone").addEventListener(event, (e) => {
    e.preventDefault();
    $("dropzone").classList.add("drag");
  });
for (const event of ["dragleave", "drop"])
  $("dropzone").addEventListener(event, (e) => {
    e.preventDefault();
    $("dropzone").classList.remove("drag");
    if (event === "drop") uploadFiles(e.dataTransfer.files);
  });
$("samples").addEventListener("change", async (event) => {
  const id = event.target.value;
  if (!id || state.busy) return;
  setBusy(true);
  $("queue").textContent = "Analyzing reference capture…";
  try {
    showResult(
      await api("/api/analyze/sample", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sample_id: id }),
      }),
    );
  } catch (error) {
    notice(error.message, true);
  } finally {
    setBusy(false);
    event.target.value = "";
  }
});
for (const id of ["search", "verdict", "protocol", "sort"])
  $(id).addEventListener(id === "search" ? "input" : "change", () => {
    state.page = 0;
    renderFlows();
  });
$("prev").addEventListener("click", () => {
  state.page--;
  renderFlows();
});
$("next").addEventListener("click", () => {
  state.page++;
  renderFlows();
});
$("new").addEventListener("click", () => {
  reset();
  $("file").click();
});
$("refresh").addEventListener("click", refresh);
$("export").addEventListener("click", () => {
  if (state.result)
    download(state.result, `trafficscan-${state.result.id}.json`);
});
$("csv").addEventListener("click", () => {
  const keys = [
    "id",
    "prediction",
    "source",
    "sport",
    "destination",
    "dport",
    "protocol",
    "packets",
    "bytes",
    "confidence",
    "entropy",
    "timestamp",
  ];
  const safe = (value) =>
    '"' +
    String(value)
      .replace(/^[=+@-]/, "'$&")
      .replaceAll('"', '""') +
    '"';
  const csv = [
    keys.join(","),
    ...filteredFlows().map((flow) =>
      keys.map((key) => safe(flow[key])).join(","),
    ),
  ].join("\r\n");
  download(csv, "trafficscan-flows.csv", "text/csv");
});
$("export-flow").addEventListener("click", () =>
  download(state.selected, `flow-${state.selected.id}.json`),
);
$("close-detail").addEventListener("click", () => $("detail").close());
$("credentials").addEventListener("click", () => $("auth-dialog").showModal());
$("auth-cancel").addEventListener("click", () => $("auth-dialog").close());
$("auth-form").addEventListener("submit", (event) => {
  event.preventDefault();
  state.key = $("api-key").value;
  sessionStorage.setItem("traffic-key", state.key);
  $("api-key").value = "";
  $("auth-dialog").close();
  refresh();
});
document.addEventListener("keydown", (event) => {
  if (
    event.key === "/" &&
    !["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement.tagName) &&
    !$("detail").open &&
    !$("auth-dialog").open
  ) {
    event.preventDefault();
    switchView("investigate");
    $("search").focus();
  }
});
reset();
refresh();
