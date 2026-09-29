# Project Implementation Phase Notes

This document tracks our step-by-step progress in building the full-stack system and web interface for **PCAP-to-Image Malware Fingerprinting**.

---

## Roadmap Overview

| Phase | Title | Description | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Model Training & Checkpoint** | Train `TrafficCNN` on 6,000 images and save `best_model.pth` | 🟢 Completed |
| **Phase 2** | **Backend Inference API** | Build FastAPI server + inference pipeline (`classification/infer.py`) | 🟢 Completed |
| **Phase 3** | **Cybersecurity Web Dashboard** | Modern dark-mode UI with PCAP uploader, byte visualizer & metrics | 🟢 Completed |
| **Phase 4** | **End-to-End Verification** | Test PCAP uploads, image generation, real-time predictions & docs | 🟢 Completed |

---

## Phase 1: Model Training & Checkpoint

### Goal
Generate a reliable, saved model file (`ml/checkpoints/best_model.pth`) so the web dashboard can make real-time predictions.

### What was done:
1. **Script ([ml/train_model.py](file:///c:/Users/Ritheesh/Desktop/WORK/Projects/CN_CBP2k26/ml/train_model.py))**:
   - Loaded 6,000 images (2,000 Benign, 2,000 Botnet, 2,000 DDoS) from `data/processed/`.
   - Divided into 70% Train (4,200), 15% Validation (900), 15% Test (900).
   - Trained `TrafficCNN` with early stopping and saved best checkpoint.
2. **Verification ([ml/verify_checkpoint.py](file:///c:/Users/Ritheesh/Desktop/WORK/Projects/CN_CBP2k26/ml/verify_checkpoint.py))**:
   - Verified that `ml/checkpoints/best_model.pth` loads correctly.
   - Tested on dummy and real traffic image tensors with valid softmax output.
3. **Artifact Created**:
   - `ml/checkpoints/best_model.pth` ready for backend inference.

---

## Phase 2: Backend Inference API

### Goal
Build a high-performance backend API that connects network packet capture files to our trained CNN model and sends prediction telemetry to the browser.

### What was done:
1. **Inference Pipeline ([classification/infer.py](file:///c:/Users/Ritheesh/Desktop/WORK/Projects/CN_CBP2k26/classification/infer.py))**:
   - Implemented `TrafficClassifier` to extract first 4,096 bytes from PCAP via Scapy.
   - Reshaped bytes into 64×64 grayscale fingerprint and generated base64 PNGs (original + 512×512 zoomed).
   - Added Shannon entropy calculation, byte telemetry (min, max, mean), and formatted 128-byte hex dump.
   - Added graceful fallback for raw packet streams and direct image uploads.
2. **FastAPI Server ([api/server.py](file:///c:/Users/Ritheesh/Desktop/WORK/Projects/CN_CBP2k26/api/server.py))**:
   - `GET /api/health` — Returns system status, loaded PyTorch model, and execution device.
   - `GET /api/samples` — Lists available preloaded PCAP datasets (Benign, DDoS, Botnet).
   - `POST /api/analyze/sample` — One-click analysis of preloaded captures.
   - `POST /api/analyze/upload` — Direct upload handler for `.pcap`, `.pcapng`, or `.png` files.
   - Static mounting to serve the web dashboard on `/`.
3. **Unit Tests & Verification ([api/test_api.py](file:///c:/Users/Ritheesh/Desktop/WORK/Projects/CN_CBP2k26/api/test_api.py))**:
   - Verified all endpoints using Starlette `TestClient`. All tests passed with HTTP 200 responses.

---

## Phase 3 & 4: Cybersecurity Web Dashboard & End-to-End Verification

### Goal
Design and deploy a state-of-the-art SOC web dashboard for live traffic inspection and threat fingerprinting, and verify all interactions end-to-end.

### What was done:
1. **Frontend Architecture ([frontend/](file:///c:/Users/Ritheesh/Desktop/WORK/Projects/CN_CBP2k26/frontend))**:
   - **`index.html`**: Header with live engine status dock, 5-stage pipeline ribbon, drag-and-drop ingestion card, 1-click preloaded dataset list, active threat verdict banner, probability breakdown bars, 2D matrix visualizer, telemetry grid, and terminal hex dump.
   - **`styles.css`**: Premium dark-mode cyber defense aesthetic (`#070a12`), glassmorphism, radar scan graphic, pulsing indicators, and responsive grid.
   - **`app.js`**: Dynamic API integration with async file upload, progress states, interactive matrix zoom toggle (64×64 native vs 512×512 HD), pixel grid toggle, and clipboard hex copy.
2. **Server Execution**:
   - Launched the application on `http://127.0.0.1:8000`.
3. **Automated Verification**:
   - Browser subagent tested page load, status indicators, 1-click dataset analysis, probability bar animation, 2D fingerprint image rendering, Shannon entropy telemetry, and matrix view toggles. All features functioned as expected.

---

## Future Phase (Locked): Accuracy Upgrade Roadmap (74% – 94% Target)

### Current Baseline
- **Overall Accuracy**: 42.11% (DDoS Recall: 93.3%, Botnet Recall: 24.8%, Benign Recall: 11.5%)
- **Bottleneck**: Arbitrary continuous 4,096-byte chunk slicing from raw PCAPs fragments network headers and leaves >90% of pixels as empty black zero-padding.

### Locked Action Plan for Future Execution
1. **Packet-Compact Dataset Generation**:
   - Run `data_processing/packet_compact_convert.py` to extract 2,000 packets/class as 20×20 grayscale images (400 bytes/image).
   - Preserves complete Ethernet, IP, TCP/UDP headers and early payload starting at pixel (0,0) with zero wasted padding.
2. **High-Accuracy Model Training**:
   - Run `ml/train_packet_compact.py` with class weighting and early stopping.
   - Tested benchmark performance from repository experiments:
     - Chronological split: **74.00% accuracy** (Macro F1: 0.7418, DDoS F1: 0.9010)
     - Stratified split: **94.67% accuracy** (Macro F1: 0.9469)
3. **Inference Pipeline Integration**:
   - Update `classification/infer.py` to ingest 20×20 packet frames, keeping the 512×512 HD preview for the web dashboard.



