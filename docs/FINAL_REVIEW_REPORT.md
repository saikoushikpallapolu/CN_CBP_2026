# TrafficScan review build

> Latest update, 29 October: the longevity replay was stopped by the user after about 48 minutes/5,970 analyses and was not restarted. The new **Test & demo** workflow is documented in [DEMO_GUIDE.md](DEMO_GUIDE.md). Two new training challengers and a threshold policy were rejected; see [MODEL_IMPROVEMENT_RESULTS.md](MODEL_IMPROVEMENT_RESULTS.md). These updates supersede the running-audit statements below.

Updated 28 October 2026. **The local GPU product is running at http://127.0.0.1:8000.** It is ready for functional review; enterprise production sign-off has not passed.

## Review and operate

See [the review guide](REVIEW_GUIDE.md). Start/resume with `python -m scripts.review_app start`, inspect with `status`, and stop with `stop`. Docker Desktop must be running. History persists in `artifacts/review/`. The service binds only to localhost and uses a read-only container, dropped capabilities and bounded resources. Review mode permits visibly marked experimental predictions. Production compose requires authentication and forces UNKNOWN while release gates fail.

The interface provides multi-file PCAP/PCAPNG intake, real reference captures, searchable/filterable/sortable flow evidence, pagination, grayscale/hex inspection, JSON/CSV export, saved investigations, source provenance and measured model gates. CPU staging details remain on the technical validation page; the main workspace identifies the active GPU runtime concisely.

## Measured results

The frozen candidate trained on **26,068 bursts**: 9,838 benign, 3,716 botnet and 12,514 DDoS. Calibration used 635 validation bursts. The source-held-out test contains 7,209 bursts from Tuesday, Friday and CTU-13 scenario 10. Capture groups are disjoint.

| Metric | PyTorch candidate | Active TensorRT INT8 |
|---|---:|---:|
| Flow accuracy | 98.571% | 98.654% |
| Represented-packet accuracy | 98.856% | 98.979% |
| Macro F1 | 0.87453 | 0.88377 |
| Benign represented packets escalated | 3.023% | 2.983% |
| Expected calibration error | 0.14542 | 0.13125 |

The final synchronized GPU audit measured **0.581 ms median / 0.779 ms p95 per 64 flow bursts**, including pinned host/device transfers. A separate warmed 1,024-packet capture benchmark measured **22.595 ms median / 25.616 ms p95**, with median observed throughput of 45,528.5 packets/s. These offline measurements exclude HTTP upload, live NIC ingestion and waiting for flow context; they do not establish wire latency or million-packet/second line rate.

TensorRT agrees with float32 on **99.889%** of test predictions. Maximum held-out logit difference is 3.559, so numerical identity is not claimed. Engine-specific temperature scaling used actual validation outputs before test evaluation. Its temperature is 1.796989. Calibration reliability still fails the 0.05 error target.

Packet weighting counts only packets represented in retained first-16-packet bursts, not every raw-capture packet. The test has only 31 botnet bursts, limiting conclusions about botnet performance. Accuracy and measured model latency pass; macro F1, benign escalation and calibration do not.

Evidence: [GPU audit](validation/final-tensorrt-audit.json), [capture benchmark](validation/final-gpu-benchmark.json), [GPU HTTP checks](validation/final-deployment-gpu.json), [export audit](validation/final-export-test-audit.json).

## Completed acquisition and additional validation

Both 21 February ZIP members passed full size/CRC checks: **18,275,068,082 bytes** for part 1 and **2,123,980,800 bytes** for part 2. Prepared subsets contain 372,828 UDP packets and 171,452 HOIC packets. The original UDP calibration subset is byte-identical to the subset prepared from the fully verified member. The earlier prefix-integrity limitation is resolved.

Both segments share one validation capture group. Train/test arrays remain unchanged. Prepared-subset provenance is retained separately from capture groups so a segmented file cannot create false source independence. See [integrity reconciliation](validation/final-capture-integrity.json) and [split audit](validation/final-split-audit.json).

The additional **17,151 HOIC bursts** were evaluated on the frozen GPU engine without fitting or recalibration. **All were rejected as UNKNOWN and escalated; none was accepted as benign.** Known-class argmax accuracy before rejection was only 0.00583%. This demonstrates rejection on this attack-only subset, not successful HOIC type recognition, universal zero-day detection or a benign false-positive rate. See [HOIC audit](validation/hoic-gpu-audit.json).

CTU-13 scenarios 1, 2, 9 and 10, CIC Tuesday/Wednesday/Friday, controlled normal DNS and MAWI were previously acquired with hashes and provenance. Schedule/endpoint labels still need independent flow-label auditing. Wednesday DoS is grouped with DDoS. MAWI's 471,845 packets remain unlabeled/OOD; the requested 500,000 verified clean MAWI/Tuesday packets are not established.

## Verification and fixes

- **19 Linux tests passed**, including the native parser and engine-metadata regression; Windows passed 18 with the native-extension case skipped.
- GPU HTTP checks passed for authentication, readiness enforcement, sample inference, history and security headers.
- Engine metadata now uses `.engine.json`, preserving the separate training report. The old colliding metadata was retained before restoring the candidate report from its matching checkpoint.
- Runtime audit files must match checkpoint, engine and temperature before the app displays their results. GPU latency/parity gates reflect the active audited engine.
- Windows Application Control remains enabled. CUDA training works natively; TensorRT runs in the supported Linux Docker environment.
- The model, fingerprint inspector, reference captures, history, source provenance and responsive UI were reviewed in a running browser.

## Long-run audit and remaining release gates

The current public TensorRT replay began **28 October 2026 at 00:09 IST**, with expected completion **29 October at 00:09 IST** if uninterrupted. Live progress: `artifacts/candidate_flow_resnet-gpu-stability-24h.summary.json`. `device=cpu` denotes host staging; `backend=tensorrt` executes the audited GPU engine. A snapshot is not a 24-hour pass. Keep this PC and Docker running.

The prior CPU baseline stopped after 4,923 successful analyses at about 72 minutes when Windows blocked a summary rename. The repaired logger retries locks and commits summaries once per minute; its smoke test passed. The new full-duration run remains pending.

Enterprise/campus false-positive validation and dedicated AF_XDP/DPDK NIC/GPU-ring work remain outside this public offline review build. The user selected public replay only. TLS or subnet membership is deliberately not used to bypass threat classification. No production sign-off, full SIEM parity or fastest-on-market claim is made.

The workflow was compared with [Security Onion PCAP pivots](https://docs.securityonion.net/en/2.4/pcap.html), [Malcolm/Arkime](https://malcolm.fyi/docs/arkime.html) and [Arkime](https://arkime.com/). This product covers compact capture triage and fingerprint evidence, not their full identity, case management, retention or sensor-orchestration capabilities.

## Review archive and reproduction

`artifacts/release/trafficscan-review.zip` contains code, model artifacts, frozen sanitized tensors, real reference captures and validation evidence. `REVIEW_MANIFEST.json` records each file's SHA-256; the adjacent `.sha256` verifies the archive. Raw corpora, credentials, investigation history, environments and NVIDIA libraries are excluded. GPU engines must be rebuilt for other GPU/runtime targets. See [GPU setup](GPU_DEPLOYMENT.md), [Kaggle T4 training](KAGGLE_GPU.md) and [dataset citations](../data/DATASET_CITATIONS.md).

The [earlier implementation record](PRODUCTION_IMPLEMENTATION_STATUS.md) and baseline evidence remain as history. This report supersedes its stopped/pending statements.
