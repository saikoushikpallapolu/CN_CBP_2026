# Adaptive-context research study

This is a measured first research pass, not a claim that every paper-readiness category is 9/10. The production classifier remains unchanged. Open **Research lab** for experiments, split/seed/policy comparisons, source/model hashes, metrics, final results and exports.

The completed study's [measured results and preserved evidence](research/adaptive-v1-20261101-r1/README.md) include the unfavorable final-test findings. The local reproduction ZIP is `artifacts/research/adaptive-v1-20261101-r1-reproduction.zip`; it contains frozen feature arrays and model artifacts, is excluded from Git, and needs dataset-terms review before public redistribution.

## Frozen question and method

Question: does uncertainty-driven additional packet context improve the accuracy–delay–cost trade-off relative to fixed 16-packet decisions under source shift?

The research detector observes 4 → 8 → 16 → 32 packets and requests another prefix when confidence/entropy criteria are unmet. Acceptance uses only the current prefix. Short sessions terminate on an observed boundary/idle deadline and retain their true packet count; zero padding is not counted as additional evidence. The production fingerprint remains 16×32; research inputs are k×32 bytes, with k up to 32. Neural models process the actual requested prefix size. Their number of inference calls is reported, since multiple looks are not free.

The stopping function is shared by offline decisions and the incremental harness. Tests verify no future look-ahead, escalation, short-session rejection, fixed-16 behavior and matched 1D/2D input bytes. Research models are not promoted into the serving app.

## Data protocol

The immutable `research/protocol.json` specifies prefixes, seed/epoch/sample budgets, threshold grid, validation constraints and final sources. Frozen code hashes specify remaining constants (AdamW learning rate 0.001, weight decay 0.0001, class-weighted focal loss, model widths and RF/KitNET settings). Each experiment records protocol, dataset, model, source, label-file and method-code hashes.

The final dataset contains 7,721 training, 633 validation, 3,414 development and 1,814 final sessions. Previously inspected HOIC, Rbot and normal browsing sources are development evidence. NSIS.ay and Virut are reserved from fitting, temperature calibration and policy selection. Final normal sources include independently captured browsing/home/chat traces. Related Windows captures from the same host/date are grouped together, not split between partitions.

Data are original public packets, not simulator continuations. Publisher-designated normal traces cover DNS, browsing, P2P/downloads, messaging and encrypted applications at capture level; individual application ground truth is not established. Sessions use first 32 packets, 30-second idle and SYN/ISN boundaries, bounded state and exact raw-event duplicate checks. Only label-consistent prefixes are included. Background/unmatched flows are excluded.

Important limits:

- Training/development/final capture groups are disjoint; cross-day host reuse is not ruled out for every legacy source.
- Labels rely on publisher designations or matched published intervals/endpoints; independent flow-label auditing remains pending.
- The final cohort has 1,750 normal and only 64 botnet sessions (27 NSIS.ay, 37 Virut). It has no final DoS/DDoS examples. It tests novel botnet-family transfer, not comprehensive unseen-attack detection.
- Reported three-class macro F1 includes absent classes with F1=0; a present-class metric and support counts are separate.
- Historical bounded capture prefixes and first-confirmed-session sampling do not establish contemporary enterprise representativeness.

The final holdout is opened only after model/policy locks. A cross-run exposure ledger prevents silently calling the same source untouched again. After opening, further tuning needs a new final cohort or an explicitly regression-only evaluation.

## Comparisons and ablations

Three seeds (17,42,73) and six epochs per neural configuration were executed:

- Prefix-aware 1D ResNet; a separately trained fixed-16 1D ResNet; matched-prefix 2D ResNet.
- Sanitization-off 1D model; bytes-plus-behavior hybrid model.
- Logistic and random-forest behavioral baselines.
- Author KitNET implementation on the same 18 causal behavioral features. Its source commit, MIT license and minimal import/NumPy-2 compatibility patches are preserved in `research/vendor/kitnet/UPSTREAM.json`. This is not the original full Kitsune feature-extraction pipeline. Author autoencoders use a fixed internal seed, so its repeated runs are not independent stochastic replications.

The matched 1D/2D comparison uses identical observed bytes, splits and training epoch budgets. Parameter counts and modalities are disclosed; model capacity and every possible hyperparameter are not exhaustively matched. A legacy production checkpoint is not presented as a fair retrained competitor on sources it has already seen.

Fixed 4/8/16/32, adaptive stopping and no-rejection decisions are reported. Shared-weight fixed-prefix ablations use the same selected threshold to isolate stopping effects; the dedicated fixed-16 model has its own validation-selected threshold. All candidate threshold selection uses validation data, never final data. Infeasible validation constraints are explicitly reported, not treated as passes.

The masking ablation disables sanitization within the same protocol-aware feature layout. That layout excludes raw IP address slots in both variants; this is not a full raw-IP-header ablation or a privacy guarantee.

FP32 versus QDQ INT8 was evaluated for three prefix-model seeds with the same CPU ONNX Runtime and two threads. Quantizer calibration uses training sessions; temperature and stopping policies use validation. This isolates precision without conflating CPU versus GPU. Separate same-PyTorch/device kernel timings disclose copies and excluded pipeline costs. An in-memory PNG codec experiment is separately scoped; the 2D baseline takes tensors directly and is not forced through PNG to inflate an apparent 1D advantage.

## Metrics and systems evidence

Exports include per-class/family outcomes, support, confusion matrices with an explicit review column, false attack alerts, benign review, attacks accepted as benign, accepted coverage/error, risk–coverage curves, Brier/ECE and binary attack AUROC/AUPR. Rejection never counts as correct attack-type recognition.

Capture-cluster bootstrap intervals and three-seed results are separate. Seed ranges in figures are not 95% confidence intervals. Few capture clusters and very small attack-family counts limit statistical claims regardless of how many packets are present.

The isolated harness feeds raw PCAP records at original timing at 1×, performs causal incremental inference through a bounded queue, and measures arrival-to-decision p50/p95/p99, packet depth, inference calls, memory and overload drops. Artificial clip boundaries censor incomplete sessions rather than forcing early decisions. The executed clips are short (5 seconds), and latency is conditional on completed decisions. Stress runs use explicit accelerated pacing. This does not establish NIC line rate, real prevention, full-capture performance or 24-hour stability.

The p95 context wait in development remains about 30 seconds because short incomplete sessions reach the idle deadline. A sub-millisecond model kernel is not sub-millisecond detection latency.

## Reproduction and verification

The model/data/code artifact checks passed. An initial same-machine numerical replay used a different batch size/CUDA execution profile and exceeded a 1e-4 probability tolerance. Its report is preserved. Matching the original batch256, deterministic CUDA settings and FP32 normalization reproduced all 15 neural checkpoints within the original tolerance; no model or policy was retuned. The pipeline now treats a failed verification status as a failure, rather than relying only on process exit code.

This is automated same-machine verification, not independent human reproduction. The run includes an external-review checklist and a local reproduction bundle command. Dataset redistribution rights and independent labeling/reproduction still require review. Byte-exact source is preserved by ZIP; source LF hashes also distinguish Git line-ending conversion from method changes.

With the original acquired labeled sources available:

```text
python -m research.acquire
python -m research.expand_holdout
python -m research.dataset --output artifacts/research/new-frozen.npz
python -m research.run --data artifacts/research/new-frozen.npz --run-id new-study
python -m research.precision new-study
python -m research.complete new-study
python -m research.bundle new-study --include-frozen-data
```

Never silently reuse an exposed final cohort for tuning. The reference study is `adaptive-v1-20261101-r1`. Its workbench exports contain actual results and the evidence-based scorecard, not fabricated 9s or 10s. Remaining publication blockers are a verified novel contribution, stronger independent cohorts/labels, robust constrained gains and independent reproduction.

References: [KitNET author implementation](https://github.com/ymirsky/KitNET-py), [Kitsune paper](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_03A-3_Mirsky_paper.pdf), [security-ML evaluation pitfalls](https://www.usenix.org/conference/usenixsecurity22/presentation/arp), [research reproducibility checklist](https://neurips.cc/public/guides/PaperChecklist).
