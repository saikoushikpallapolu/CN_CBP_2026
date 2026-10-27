# Production implementation status

> Historical implementation/handoff record. Work resumed and the review product is now running. See [FINAL_REVIEW_REPORT.md](FINAL_REVIEW_REPORT.md) for current measurements, completed capture verification and the active long-run audit; it supersedes stopped/pending statements below.

## Handoff: stopped at user request

Implementation work, the local server and active acquisition were stopped before committing. No background audit is currently running. The expanded candidate is saved locally and remains experimental. Downloaded captures, weights, environments and NVIDIA libraries are intentionally excluded from Git.

The Linux TensorRT INT8 engine compiled and ran successfully. Its recorded held-out result was **98.654% flow accuracy / 0.88377 macro F1**, with **99.889% agreement** against float32. Synchronized 64-flow inference, including pinned-host transfers, measured **0.706 ms median / 1.561 ms p95**. Benign represented-packet escalation was **3.244%**. See `docs/validation/tensorrt-audit.json`. These measurements supersede earlier pending TensorRT statements below.

Remaining validation: finish the resumable 21 February archive download and whole-member CRC/HOIC extraction; rerun the newly added engine-specific temperature-refit audit; execute the final capture-level GPU benchmark and GPU-container HTTP smoke check; run a complete 24-hour public replay with the repaired logger. The baseline replay stopped after 4,923 successful analyses at about 72 minutes because Windows blocked a summary-file rename. The repaired logger passed a short replay smoke test, but the full-duration replacement was not started before the stop request. Accuracy passed on the limited holdout; macro F1, benign escalation, calibration and enterprise/NIC validation remain incomplete or failed. No production sign-off is claimed.

Updated 27 October 2026. This is the execution record for `PRODUCTION_IMPLEMENTATION_PLAN.md`. **The project has not passed enterprise production sign-off.** Code, downloaded subsets and measured results must be distinguished from hardware-dependent milestones and performance targets.

**Latest expanded GPU candidate:** 26,068 training bursts (9,838 benign / 3,716 botnet / 12,514 DDoS), 635 validation bursts and 7,209 source-held-out test bursts. It achieved **98.571% flow accuracy, 98.856% packet-weighted accuracy and 0.87453 macro F1**. Of 2,144 Friday DDoS bursts, 2,073 were correctly classified. Benign packet escalation is **3.023%** and expected calibration error is **0.14542**. Accuracy, training count and source-diversity gates now pass; macro F1, benign escalation, calibration and operational gates still fail. This is a limited research evaluation, not enterprise certification.

Packet-weighted metrics count packets represented by the retained first-16-packet bursts. They do not score every packet in the original raw captures. Repeated flood packets do not become independent training examples merely by increasing the byte budget.

The candidate adds separately bounded LOIC-HTTP and LOIC-UDP training windows from 20 February 2018 and reserves 21 February for validation. The training capture contains 183,293 HTTP and 372,828 UDP packets; per-window sampling retains 10,000 HTTP and 10 UDP independent flow bursts, avoiding an earlier-window cap that could omit UDP. Validation selection averages cross entropy per class. The 21 February UDP subset currently uses complete records from an interrupted decompressed prefix, explicitly marked `whole_archive_member_crc_verified=false`; full archive CRC verification and HOIC acquisition remain in progress. Temperature calibration has only 24 DDoS validation bursts.

Float ONNX matches PyTorch numerically. CPU INT8 agreed with float32 on 99.917% of test predictions and achieved 98.627% flow accuracy. The symmetric TensorRT-compatible graph agreed on 99.861% and achieved 98.682% flow accuracy in ONNX Runtime. These graph checks do not establish TensorRT execution or latency.

The following older metrics describe the preserved baseline (`artifacts/baseline/`).

The user selected public dataset replay for the duration test. The baseline run completed 4,923 successful analyses over approximately 72 minutes, then Windows denied a summary-file rename. Its `.context.json` records the interruption; no 24-hour pass is claimed. The runner now retries file locks and commits summaries once per minute, while retaining per-analysis JSONL. A fresh accelerated-model run follows GPU verification. This replay does not establish campus ground truth. The hardened production image passed HTTP checks for authentication, readiness, sample inference, history and security headers (`artifacts/deployment-smoke.json`). Browser exports were inspected: JSON contained 63 flows; a UDP filter exported exactly 38 UDP rows. A reviewed dashboard screenshot is saved in `docs/validation/dashboard.png`.

The executed run trained on **13,189 flow bursts**, calibrated on **621**, and tested on **7,209** from unseen captures. It achieved **69.91% flow accuracy**, **53.43% packet-weighted accuracy**, and **0.4754 macro F1**. Every Friday DDoS holdout flow was misclassified before rejection. Benign packet escalation (attack or UNKNOWN) was **24.43%** and held-out expected calibration error was **0.3937**. These results fail the requested thresholds. Validation includes only 10 independent CSE DDoS sessions despite hundreds of thousands of raw flood packets.

On the 1,024-packet Monday reference, measured CPU medians were **27.28 ms / 37,540 packets/s** for PyTorch and **28.50 ms / 35,938 packets/s** for ONNX INT8. These are offline, warmed-up capture benchmarks, not per-packet wire latency or GPU line-rate evidence. INT8 agreed with float32 on **99.972%** of the full held-out set but did not improve this CPU benchmark.


| Roadmap requirement | Implementation / evidence | Status |
|---|---|---|
| Remove capture-day labels | CTU bidirectional interval/5-tuple joins; CIC timestamp + endpoint/NAT rules; background/unknown excluded | Implemented; independent label audit remains |
| Independent capture provenance | Source IDs, capture and label-range SHA-256, acquisition status in `data/external/acquisition.json` | Implemented for bounded subsets |
| Tuesday benign enrichment | Attack-free pre-09:15 Atlantic interval; Tuesday is not globally benign | Acquired subset |
| MAWI enrichment | 471,845 packets acquired; excluded from supervised training without annotations | Raw OOD subset acquired; annotation review required |
| CTU-13 scenarios 1, 2, 9, 10 | Bounded raw captures and distributed official label ranges; unmatched traffic excluded | Acquisition recorded per scenario in manifest |
| CIC Friday DDoS | Binary-search attack-window selection within PCAPNG; published LOIC endpoint/time filter | Acquired subset |
| CSE-CIC-IDS2018 LOIC-UDP | Extracted 20 February victim member; prepared 556,121 HTTP/UDP packets; per-window sampling and independent 21 February UDP validation | Training subset acquired; full validation-member CRC and flow-label audit pending |
| 500,000 verified clean MAWI/Tuesday packets | Raw traffic is not accepted as verified benign without ground truth | Not met |
| MAC/IP masking | Protocol-aware Ethernet/VLAN/IPv4/IPv6 handling | Implemented and tested |
| Ephemeral port masking | Both transport ports >1024 masked; well-known ports retained | Implemented and tested |
| Derived identity fields | IP/TCP/UDP checksums, IPv4 IDs, TCP sequence/ACK and timestamps masked | Implemented |
| 16 × 32 flow images | First 16 observed packets per bidirectional session; idle timeout and bounded session table; browser grayscale renderer | Implemented |
| Training/serving parity | Shared `data_processing/production.py`, representation version, matching normalization and checkpoint metadata | Implemented |
| 1D ResNet-18 | Four two-block residual stages with compact 16-channel stem | Implemented; trained artifact is experimental |
| Focal loss gamma 2 | Data-frequency weights, not fixed heuristic weights | Implemented and tested |
| Cosine annealing / early stopping | Seeded trainer, validation selection, untouched test scoring | Implemented; limited coverage reported |
| Strict source holdout / Experiment 11 | Source-overlap rejection and exact raw-event deduplication; naturally identical sanitized fingerprints retained | Implemented; all classes present in each split |
| Temperature scaling | Fit on validation logits only; separate INT8 temperature; held-out calibration error measured | Algorithm executed; confidence reliability target failed |
| Confidence / entropy rejection | Confidence <0.75 or normalized entropy >0.8; UNKNOWN is distinct from benign | Implemented and tested |
| No PIL/base64 inference path | Direct arrays/tensors; fingerprint rendered in browser | Implemented |
| Batched inference / bounded memory | Batches of 64 flow tensors, bounded active sessions, packet and flow limits | Implemented |
| C++ / SIMD preprocessing | Optional native buffer normalizer; portable loop and AVX2 path; Torch fallback | Compiled in Linux Docker image and exercised in tests; Windows MSVC unavailable |
| Memory-mapped native capture preprocessing | Native bounded classic-PCAP parser consumes memory-mapped buffers; PCAPNG and large archives retain streaming fallback | Implemented and parity-tested in Docker |
| AF_XDP / DPDK zero-copy NIC ingestion | Requires dedicated compatible sensor, kernel/NIC setup and validation | Not implemented on this Windows host |
| Ring buffer from NIC into GPU | Offline capture batches exist; NIC/GPU shared-memory pipeline is separate | Not implemented |
| ONNX export | Numerical Torch/ONNX parity assertion, version and checkpoint hash metadata | Implemented and exercised |
| Static INT8 quantization | Validation-only QDQ calibration; agreement/logit error report | Implemented and exercised; independent accuracy audit pending |
| TensorRT INT8 | Symmetric QDQ engine builder, Torch-CUDA and CUDA-Python pinned-buffer adapters | CUDA training verified on RTX 4060; Windows Application Control blocks TensorRT bindings; isolated Linux GPU path under validation |
| TLS/subnet fast path | No automatic benign decision based on subnet or TCP/443; those signals cannot validate benign behavior | Deliberately not used as a threat bypass |
| FastAPI / gRPC service | FastAPI provides the plan's HTTP serving path; gRPC is not required to use it | FastAPI implemented; no gRPC service |
| Upload and API hardening | Size/type/magic validation, malformed rejection, chunked body bound, authorization before parsing, same-origin frontend, security headers and upload backpressure | Implemented; 18 tests passed in Linux verification image |
| Deployment packaging | Non-root Docker image, read-only compose service, loopback binding, resource bounds, proxy settings, health/readiness split | Image built; 18 Linux tests passed; production HTTP smoke checks passed |
| 24-hour stability audit | Public replay/RSS/error JSONL runner, as selected by user | Running; no full-duration pass claimed |
| Real campus benign false-positive audit | Requires an authorized campus capture and independently verified ground truth | Not run |
| >95% accuracy, >0.94 macro F1, <0.1% benign FPR | Trainer emits actual metrics and individual gates | Accuracy passed on limited holdout; macro F1 and benign escalation failed |
| <0.5 ms/packet or <5 ms/64 packets | Model and end-to-end benchmark tools; model batch explicitly means 64 flows | End-to-end target not established |
| Identity scrambling check | Real-packet address/port/checksum mutation audit | 3,784 packets, zero input changes in recorded audit |
| Fastest on market / line-rate guarantees | No evidence supports these claims | Not claimed |

## Data-label details

CTU botnet PCAPs were captured on infected VM interfaces, while the reference Argus flows came from a router capture. For scenario 1, matching TCP SYN events showed a roughly 0.47-second clock difference. The builder estimates a bounded median offset from at least 20 matching SYN events, records residuals and join tolerance, and excludes inconsistent or unlabeled bursts. This is timestamp synchronization, not model-accuracy tuning. The resulting labels still require independent inspection before a production claim.

Distributed label-range downloads intentionally provide incomplete coverage. A row is accepted only if the complete record is available and its label, 5-tuple and interval match. A packet from an infected host is not automatically labeled malicious. The complete dataset therefore has fewer trustworthy examples than the raw packet count suggests. Each build reports excluded and accepted counts.

CIC Wednesday Hulk is a **DoS** attack, grouped into the existing `ddos` class for compatibility. Friday LOIC is the independent holdout. The taxonomy should be expanded if separate DoS/DDoS discrimination is required. The acquired excerpts are not substitutes for a diverse, fully labeled enterprise corpus.

## UI benchmark and scope

The investigation workflow was compared against official documentation for [Security Onion PCAP pivots](https://docs.securityonion.net/en/2.4/pcap.html), [Malcolm's Arkime interface](https://malcolm.fyi/docs/arkime.html), and [Arkime](https://arkime.com/). The implemented scope includes capture intake, searchable/filterable flow tables, evidence drill-down, grayscale/hex inspection, JSON/CSV export, saved investigations, source provenance and model gates. The design uses a restrained navigation rail, compact metrics, responsive panels and short labels.

This application does not provide the full SIEM, rule management, asset enrichment, case management, full-packet retention, enterprise identity, multi-user roles or sensor orchestration of those platforms. Feature parity or superiority has not been established. The UI was reviewed in a running browser, including a real capture, flow inspector, search, saved-history reload and a narrow-screen layout; a clipped mobile chart was corrected.

## Reproduce and inspect

Use the commands in the root README. Local generated evidence lives in `data/external/acquisition.json`, `data/production/dataset.json`, `ml/checkpoints/flow_resnet.json`, `ml/checkpoints/flow_resnet.export.json` and `artifacts/`. Downloaded data and generated model artifacts are intentionally ignored by Git. A concise copy of final evidence is retained under `docs/validation/`.

The legacy 74% TrafficCNN result applies only to the original within-capture experiment. Neither it nor the plan's aspirational values are performance evidence for the new model. Model, calibration, data diversity, acceleration and operational gates remain visible and must pass before enterprise sign-off.

Deployment compose sets `TRAFFICSCAN_REQUIRE_READY=1`: failed release gates force UNKNOWN while preserving experimental class suggestions. The loopback development server permits research predictions and identifies the model as experimental. `/api/ready` returns 503 until every gate passes.

The builder retains naturally identical sanitized fingerprints across independently captured sessions; a normal handshake and an attack handshake can legitimately become indistinguishable after masking. Deleting those cases would make the holdout artificially easier. Only exact timestamped raw events are deduplicated. Per-source records prevent concurrent acquisitions from erasing provenance.

## GPU and environment update

Hardware inspection confirmed an NVIDIA GeForce RTX 4060 Laptop GPU with 8 GB VRAM and driver 617.14. The isolated `.venv-gpu` now runs PyTorch 2.14.1+cu130 / CUDA 13.0. CUDA tensor execution and two complete training runs succeeded. The expanded run recorded a peak of 65,156,608 bytes allocated by Torch; this excludes driver/context memory. Windows Application Control rejected the TensorRT Python binding. That protection remains enabled. Docker's Linux container has verified NVIDIA GPU access; target-specific unmodified NVIDIA Linux libraries are acquired with official wheel RECORD SHA-256 verification for the supported Linux runtime.

Docker Desktop's Linux engine is now running. The deployment image and a verification image built successfully, including the C++ normalizer and memory-mapped classic-PCAP parser. All 16 tests passed inside the Linux verification image. This supersedes earlier assumptions that Docker was unavailable or that the PC lacked an NVIDIA GPU.
