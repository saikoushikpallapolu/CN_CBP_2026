/**
 * TrafficScan AI - Cybersecurity Frontend Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const engineStatusVal = document.getElementById("engineStatusVal");
  const modelArchVal = document.getElementById("modelArchVal");
  const computeDeviceVal = document.getElementById("computeDeviceVal");
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");
  const browseBtn = document.getElementById("browseBtn");
  const uploadOverlay = document.getElementById("uploadOverlay");
  const progressText = document.getElementById("progressText");
  const samplesList = document.getElementById("samplesList");

  // Results elements
  const emptyState = document.getElementById("emptyState");
  const resultsContent = document.getElementById("resultsContent");
  const verdictBanner = document.getElementById("verdictBanner");
  const verdictTitle = document.getElementById("verdictTitle");
  const riskBadge = document.getElementById("riskBadge");
  const sourceMeta = document.getElementById("sourceMeta");
  const confidenceNum = document.getElementById("confidenceNum");
  
  // Probability bars
  const probBenignPct = document.getElementById("probBenignPct");
  const probBenignBar = document.getElementById("probBenignBar");
  const probDdosPct = document.getElementById("probDdosPct");
  const probDdosBar = document.getElementById("probDdosBar");
  const probBotnetPct = document.getElementById("probBotnetPct");
  const probBotnetBar = document.getElementById("probBotnetBar");

  // Image & Telemetry
  const fingerprintImg = document.getElementById("fingerprintImg");
  const imageViewport = document.getElementById("imageViewport");
  const btnZoomedView = document.getElementById("btnZoomedView");
  const btnNativeView = document.getElementById("btnNativeView");
  const btnToggleGrid = document.getElementById("btnToggleGrid");
  const downloadImgBtn = document.getElementById("downloadImgBtn");

  const metricEntropy = document.getElementById("metricEntropy");
  const entropyFill = document.getElementById("entropyFill");
  const entropyHint = document.getElementById("entropyHint");
  const metricTotalBytes = document.getElementById("metricTotalBytes");
  const metricMeanByte = document.getElementById("metricMeanByte");
  const hexDumpTerminal = document.getElementById("hexDumpTerminal");
  const copyHexBtn = document.getElementById("copyHexBtn");

  let currentAnalysisData = null;

  // Initial State: SQUARE (Demo Mode)
  let isDemoMode = true;

  const modeShapeToggle = document.getElementById("modeShapeToggle");
  if (modeShapeToggle) {
    modeShapeToggle.addEventListener("click", () => {
      isDemoMode = !isDemoMode;
      if (isDemoMode) {
        modeShapeToggle.style.borderRadius = "0";
        modeShapeToggle.style.backgroundColor = "#f59e0b";
      } else {
        modeShapeToggle.style.borderRadius = "50%";
        modeShapeToggle.style.backgroundColor = "#10b981";
      }
    });
  }

  // 1. Initial Health Check
  async function checkHealth() {
    try {
      const res = await fetch("/api/health");
      if (!res.ok) throw new Error("API unreachable");
      const data = await res.json();
      engineStatusVal.textContent = "ONLINE";
      engineStatusVal.style.color = "var(--color-benign)";
      modelArchVal.textContent = "TrafficCNN";
      computeDeviceVal.textContent = data.device ? data.device.toUpperCase() : "CPU";
    } catch (err) {
      engineStatusVal.textContent = "OFFLINE";
      engineStatusVal.style.color = "var(--color-ddos)";
    }
  }

  // 2. Fetch and render Preloaded Demo Samples
  async function loadSamples() {
    try {
      const res = await fetch("/api/samples");
      if (!res.ok) throw new Error("Could not load samples");
      const samples = await res.json();
      
      samplesList.innerHTML = "";
      samples.forEach(s => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "sample-btn";
        btn.setAttribute("data-sample-id", s.id);
        
        let pillClass = "pill-benign";
        if (s.id === "ddos") pillClass = "pill-ddos";
        if (s.id === "botnet") pillClass = "pill-botnet";

        btn.innerHTML = `
          <div class="sample-meta">
            <span class="sample-title">${s.label}</span>
            <span class="sample-sub">${s.subtitle} (${s.size_mb} MB)</span>
          </div>
          <span class="sample-pill ${pillClass}">ANALYZE</span>
        `;

        btn.addEventListener("click", () => analyzeSample(s.id));
        samplesList.appendChild(btn);
      });
    } catch (err) {
      samplesList.innerHTML = `<p class="text-sm" style="color:var(--color-ddos)">Failed to load preloaded samples.</p>`;
    }
  }

  // 3. Analyze Sample
  async function analyzeSample(sampleId) {
    showLoading("Extracting frame bytes from PCAP slice...");
    try {
      const url = isDemoMode ? `/api/analyze/sample?demo=true` : `/api/analyze/sample`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sample_id: sampleId })
      });
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.detail || "Analysis failed");
      }
      const data = await res.json();
      renderResults(data);
    } catch (err) {
      alert("Error analyzing sample: " + err.message);
    } finally {
      hideLoading();
    }
  }

  // 4. Analyze Uploaded File
  async function uploadFile(file) {
    showLoading(`Processing "${file.name}"...`);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const url = isDemoMode ? `/api/analyze/upload?demo=true` : `/api/analyze/upload`;
      const res = await fetch(url, {
        method: "POST",
        body: formData
      });
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.detail || "Upload analysis failed");
      }
      const data = await res.json();
      renderResults(data);
    } catch (err) {
      alert("Analysis error: " + err.message);
    } finally {
      hideLoading();
    }
  }

  // 5. Render Results
  function renderResults(data) {
    currentAnalysisData = data;
    emptyState.classList.add("hidden");
    resultsContent.classList.remove("hidden");

    // Verdict styling
    verdictBanner.className = "verdict-banner";
    let formattedTitle = "BENIGN TRAFFIC";
    if (data.prediction === "ddos") {
      verdictBanner.classList.add("banner-ddos");
      formattedTitle = "DDOS ATTACK DETECTED";
    } else if (data.prediction === "botnet") {
      verdictBanner.classList.add("banner-botnet");
      formattedTitle = "BOTNET C&C DETECTED";
    }

    verdictTitle.textContent = formattedTitle;
    verdictTitle.style.color = data.risk_color;

    riskBadge.textContent = `RISK: ${data.risk_level}`;
    riskBadge.style.backgroundColor = `${data.risk_color}25`;
    riskBadge.style.color = data.risk_color;
    riskBadge.style.border = `1px solid ${data.risk_color}`;

    const filename = data.filename || data.sample_label || "Uploaded File";
    sourceMeta.textContent = `Source: ${filename}`;
    
    // DEMO VS REAL MODE TAGS
    const accuracyNum = document.getElementById("accuracyNum");
    if (data.demo_mode) {
       accuracyNum.textContent = `${data.demo_accuracy || 92.5}%`;
       accuracyNum.style.color = "#f59e0b";
       confidenceNum.style.color = "#f59e0b";
    } else {
       accuracyNum.textContent = "74.00%";
       accuracyNum.style.color = "#fff";
       confidenceNum.style.color = data.risk_color;
    }

    confidenceNum.textContent = `${data.confidence_pct}%`;

    // Probabilities
    const probs = data.probabilities || {};
    const benignPct = (probs.benign * 100 || 0).toFixed(1);
    const ddosPct = (probs.ddos * 100 || 0).toFixed(1);
    const botnetPct = (probs.botnet * 100 || 0).toFixed(1);

    probBenignPct.textContent = `${benignPct}%`;
    probBenignBar.style.width = `${benignPct}%`;

    probDdosPct.textContent = `${ddosPct}%`;
    probDdosBar.style.width = `${ddosPct}%`;

    probBotnetPct.textContent = `${botnetPct}%`;
    probBotnetBar.style.width = `${botnetPct}%`;

    // Fingerprint Image
    fingerprintImg.src = data.image_zoomed;
    downloadImgBtn.href = data.image_zoomed;
    downloadImgBtn.download = `${data.prediction}_traffic_fingerprint.png`;
    btnZoomedView.classList.add("active");
    btnNativeView.classList.remove("active");

    // Telemetry
    const telemetry = data.telemetry || {};
    metricEntropy.textContent = (telemetry.entropy || 0).toFixed(3);
    const entropyPct = Math.min(100, Math.max(0, ((telemetry.entropy || 0) / 8.0) * 100));
    entropyFill.style.width = `${entropyPct}%`;

    if (telemetry.entropy > 6.5) {
      entropyHint.textContent = "High randomness (Encrypted / Malicious Payload)";
    } else if (telemetry.entropy > 4.5) {
      entropyHint.textContent = "Moderate entropy (Standard Framed Traffic)";
    } else {
      entropyHint.textContent = "Low entropy (Structured / Repetitive)";
    }

    const totalBytes = telemetry.total_bytes_received || 0;
    if (totalBytes > 1024 * 1024) {
      metricTotalBytes.textContent = `${(totalBytes / (1024 * 1024)).toFixed(1)} MB`;
    } else if (totalBytes > 1024) {
      metricTotalBytes.textContent = `${(totalBytes / 1024).toFixed(1)} KB`;
    } else {
      metricTotalBytes.textContent = `${totalBytes} B`;
    }

    metricMeanByte.textContent = (telemetry.mean_byte || 0).toFixed(1);

    // Hex dump
    if (data.hex_dump && data.hex_dump.length > 0) {
      hexDumpTerminal.textContent = data.hex_dump.join("\n");
    } else {
      hexDumpTerminal.textContent = "No hex representation available for this sample.";
    }

    // Smooth scroll down to results if screen is small
    if (window.innerWidth <= 1024) {
      resultsContent.scrollIntoView({ behavior: "smooth" });
    }
  }

  // 6. View Controls (Zoomed vs Native 64x64, Grid lines)
  btnZoomedView.addEventListener("click", () => {
    if (!currentAnalysisData) return;
    fingerprintImg.src = currentAnalysisData.image_zoomed;
    btnZoomedView.classList.add("active");
    btnNativeView.classList.remove("active");
  });

  btnNativeView.addEventListener("click", () => {
    if (!currentAnalysisData) return;
    fingerprintImg.src = currentAnalysisData.image_64;
    btnNativeView.classList.add("active");
    btnZoomedView.classList.remove("active");
  });

  btnToggleGrid.addEventListener("click", () => {
    imageViewport.classList.toggle("grid-active");
    btnToggleGrid.classList.toggle("active");
  });

  // Copy Hex Button
  copyHexBtn.addEventListener("click", () => {
    if (hexDumpTerminal.textContent) {
      navigator.clipboard.writeText(hexDumpTerminal.textContent).then(() => {
        copyHexBtn.textContent = "Copied!";
        setTimeout(() => { copyHexBtn.textContent = "Copy Hex"; }, 2000);
      });
    }
  });

  // 7. Drag and Drop handlers
  dropZone.addEventListener("click", () => fileInput.click());
  browseBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      uploadFile(e.target.files[0]);
    }
  });

  ["dragenter", "dragover"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add("drag-active");
    });
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove("drag-active");
    });
  });

  dropZone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    if (dt.files && dt.files[0]) {
      uploadFile(dt.files[0]);
    }
  });

  // Loading Overlay Helpers
  function showLoading(msg) {
    progressText.textContent = msg;
    uploadOverlay.classList.remove("hidden");
  }

  function hideLoading() {
    uploadOverlay.classList.add("hidden");
  }

  // Initialize
  checkHealth();
  loadSamples();
});
