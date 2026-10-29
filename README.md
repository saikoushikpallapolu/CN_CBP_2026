# TrafficScan

> Response update: Traffic stream now supports monitor-only, simulated blocking/rate-limiting, and pause-on-threat. UNKNOWN is labeled Uncertain / review. Behavioral models were trained and evaluated but remain advisory because promotion checks failed. Known virtual scenarios include explicitly labeled repeated reference continuation. See [response and behavioral evaluation](docs/RESPONSE_AND_BEHAVIOR.md).


**Animated workspace:** connect the virtual sensor **192.0.2.10** on the main Traffic stream screen, or upload a capture. [Wave/simulation controls and meaning](docs/STREAM_SIMULATION.md). The virtual sensor is local recorded-data replay; no attack traffic is transmitted.

**Present/test the app:** open **Traffic stream → Connect sensor** for packet-by-packet replay and threat logs. **Model & validation** shows paired timing savings and held-out metrics. [Demo guide](docs/DEMO_GUIDE.md) · [Latest model experiments and limitations](docs/MODEL_IMPROVEMENT_RESULTS.md). The longevity replay is stopped; no live laptop traffic is captured.

**GPU review build:** [localhost:8000](http://127.0.0.1:8000) · [Review guide](docs/REVIEW_GUIDE.md) · [Final measured report](docs/FINAL_REVIEW_REPORT.md). Start/stop with `python -m scripts.review_app start` / `stop`.

Local network-capture investigations with sanitized flow fingerprints and a compact 1D residual classifier.

The active v2 pipeline reads PCAP/PCAPNG, groups bidirectional traffic into bursts of up to 16 packets, extracts 32 protocol-aware bytes per packet, and runs batched inference. MAC/IP identities, ephemeral ports, checksums, TCP sequence identifiers and timestamps are masked before model input. Grayscale fingerprints are rendered by the browser after inference.

**Deployment status is evidence-based.** `/api/ready` returns 503 until all release gates pass. A missing or incompatible checkpoint produces UNKNOWN results while retaining packet/flow evidence. There are no filename-based demo verdicts in the active API. The historical 74% TrafficCNN result is not a result for this architecture.

The expanded GPU candidate reached **98.57% flow accuracy / 98.86% packet-weighted accuracy / 0.8745 macro F1** on held-out sources. Benign packet escalation is **3.02%**, so the detector remains experimental. The preserved baseline reached 69.91% flow accuracy. See the [measured implementation status](docs/PRODUCTION_IMPLEMENTATION_STATUS.md) and [Kaggle T4 workflow](docs/KAGGLE_GPU.md).

## Run

Python 3.10+:

```powershell
python -m pip install -r requirements-production.txt
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Open [the dashboard](http://127.0.0.1:8000). The interface supports multiple capture uploads, reference captures, flow search, verdict/protocol filters, sorting, pagination, byte-fingerprint inspection, JSON/CSV export, persistent investigations, acquisition provenance and deployment gates. Each analysis is limited to 64 MB, 100,000 packets and 4,096 bursts. Exceeding a limit returns an explicit error rather than a partial verdict.

Capture images from older models cannot be uploaded into the flow model: they do not contain session context. Original experimental modules remain for historical reproduction, but `classification/production.py` is the serving engine.

## Acquire, build, train, evaluate

```powershell
python scripts/acquire_production_data.py --mib 32
python -m scripts.cse_archive
python -m scripts.cse_archive --member pcap/UCAP172.31.69.25 --max-member-mib 1024
python -m scripts.prepare_cse
python -m scripts.cse_archive --day Wednesday-21-02-2018 --archive zip --find 172.31.69.28 --folder data/external/cse21
python -m scripts.cse_archive --day Wednesday-21-02-2018 --archive zip --member "pcap/UCAP172.31.69.28 part 1" --max-member-mib 2200 --folder data/external/cse21
python -m scripts.prepare_cse --source cse21 --input data/external/cse21/member.pcap
python -m scripts.prepare_samples
python -m data_processing.build_production --max-per-source 20000
python -m scripts.audit_identity data/production/samples/monday.pcap data/production/samples/ctu1.pcap data/external/friday/capture.pcap
python -m ml.train_production --epochs 30
python -m ml.export_production --int8
python -m ml.evaluate_export
python -m scripts.benchmark_production data/production/samples/monday.pcap
```

Install `requirements-data.txt` for archive inspection. The CSE command downloads a 968 MB compressed member and extracts an 8.49 GB PCAP. Acquisition validates HTTP range responses and capture block boundaries, records SHA-256 hashes, and stores provenance under `data/external/acquisition.json`. CIC files use PCAPNG internally even when named `.pcap`. CTU bidirectional flow labels are matched by time and bidirectional 5-tuple. Sampled label coverage is recorded; unmatched and background flows are excluded. CIC windows combine published attack times with attacker/victim endpoints, including NAT, rather than assigning labels from filenames. Those schedule-derived labels still require CSV verification before enterprise sign-off. Tuesday contains brute-force attacks, so only a conservative pre-attack interval is used for normal traffic. MAWI must not be treated as automatically clean.

Train, validation and test sources are disjoint. CTU scenario 9 normal/bot captures share one source group. Exact timestamped raw events are deduplicated; naturally identical sanitized fingerprints are retained. Training requires all three classes, uses class-frequency focal loss, cosine annealing and validation early stopping, then fits a temperature on held-out validation logits. Test data never selects the model or temperature. Validation/test coverage and rejection rate are reported; unknown benign flows count as escalations in the false-positive audit. Confidence rejection is a heuristic, not a zero-day detection guarantee.

`ml/checkpoints/flow_resnet.json` contains measured metrics, environment, sources and gates. No target accuracy or throughput is guaranteed. A batch of 64 *flow bursts* is not a batch of 64 packets; model latency excludes capture processing and waiting for context.

## Optional acceleration

```powershell
Set-Location native
python setup.py build_ext --inplace
Set-Location ..
$env:PYTHONPATH = "$PWD/native"
```

The extension requires Microsoft C++ Build Tools on Windows or a C++ compiler on Linux. Its portable loop can be compiler-vectorized; explicitly targeting AVX2 requires a compatible host. There is no AVX-512 requirement. Missing native code uses the equivalent Torch normalization path.

```powershell
$env:TRAFFICSCAN_ONNX = "$PWD/ml/checkpoints/flow_resnet.onnx"
```

ONNX export checks float32 numerical parity. Static INT8 calibration uses validation samples, never test samples. Quantized prediction agreement is reported and requires independent revalidation. TensorRT requires symmetric, zero-point-zero QDQ; keep its graph separate from the CPU quantized graph. On a CUDA/TensorRT 10 or 11 host:

```text
python -m ml.export_production --output ml/checkpoints/flow_resnet.trt.onnx --int8 --symmetric
python -m ml.build_tensorrt ml/checkpoints/flow_resnet.trt.int8.onnx --int8
python -m ml.evaluate_tensorrt
```

Set `TRAFFICSCAN_TENSORRT` to the resulting engine. Engine and checkpoint hashes must match. TensorRT compilation and inference require the target GPU and are not validated on CPU. AF_XDP/DPDK ingestion and NIC-level actions require a dedicated Linux/DPDK sensor; this application currently performs offline capture analysis. A subnet or TLS port is never used as proof that a packet is benign.

## Deployment

```powershell
$env:TRAFFICSCAN_API_KEY = '<your key>'
docker compose -f deploy/compose.yaml up --build -d
```

Compose sets `TRAFFICSCAN_REQUIRE_READY=1`, forcing UNKNOWN when release gates fail. The development server permits explicitly marked experimental predictions. The container runs as a non-root user with dropped capabilities, a read-only root filesystem, resource limits and loopback-only port binding. Configure the key through the dashboard's API credentials control. Use a TLS reverse proxy with request body/time limits before network exposure; `deploy/nginx.conf` supplies the location settings. Do not expose the unauthenticated development server publicly. Docker health checks establish liveness; `/api/ready` establishes release readiness. Container builds need a suitable Docker installation and network access.

Investigation evidence is kept in `data/production/investigations.sqlite3`, retaining the latest 100 investigations. Original upload files are not retained. Saved evidence includes endpoints and sanitized byte previews; protect the database as network evidence. Reference captures are generated locally in `data/production/samples/` and excluded from Git with other downloaded data and trained weights.

## Verify

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
node --check frontend/app.js
python -m scripts.deployment_smoke
python -m scripts.stability_audit <verified-capture.pcap> --hours 24
```

The stability tool is a replay audit. Its `.summary.json` records elapsed time, failures and peak observed RSS, and stays incomplete until the full duration elapses. The current audit uses public dataset replay as requested. A real campus traffic/false-positive audit additionally needs an authorized live capture source and independently verified benign labels.

API: `/api/health`, `/api/ready`, `/api/data`, `/api/samples`, `/api/analyze/sample`, `/api/analyze/upload`, `/api/investigations`, `/api/investigations/{id}`. Mutating and evidence endpoints honor `X-API-Key` when configured. [Interactive API documentation](http://127.0.0.1:8000/docs).

See [the original roadmap](docs/PRODUCTION_IMPLEMENTATION_PLAN.md), [implementation status](docs/PRODUCTION_IMPLEMENTATION_STATUS.md), and [source policy](data/production_sources.json). The original experiment history remains in [ml/EXPERIMENT_LOG.md](ml/EXPERIMENT_LOG.md).

Dataset attribution is recorded in [data/DATASET_CITATIONS.md](data/DATASET_CITATIONS.md).
