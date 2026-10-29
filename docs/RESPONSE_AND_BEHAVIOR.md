# Simulated response and behavioral evidence

The app now separates **byte-model prediction**, **behavioral evidence**, and **response policy**. None of these controls changes a firewall, sends attack traffic, assigns an IP address, or captures laptop traffic. Production sign-off remains pending.

## Response modes

In Traffic stream, select:

- **Monitor only:** Observe every recorded packet; accepted attack predictions produce alerts and uncertain classifications produce review actions.
- **Simulated blocking:** Accepted experimental botnet/DDoS predictions with score at least 0.75 and normalized entropy at most 0.8 produce a **would block** action. These are unchanged byte-model acceptance limits, not newly relaxed classification thresholds or an approved real-world enforcement policy.
- **Simulated rate limit · 5/s:** The same eligible connections are limited to five post-decision packets per fixed one-second window anchored at the decision timestamp. Excess packets show **would drop**. This is an illustrative policy, not a validated DDoS mitigation setting.

The simulated action targets a bidirectional protocol/address/port tuple for 30 seconds. Packets already observed at the decision remain unaffected. New TCP SYN sessions clear the previous session's simulated block. Other connections continue. Packet arrival logs are preserved; would-drop packets have red marks and log entries. The response summary counts decisions, would-drop packets and would-pass packets separately. An action can legitimately have zero dropped packets when the capture ends at its decision time.

**Uncertain / review** replaces the misleading attack-like interpretation of UNKNOWN. The API retains the `unknown` enum for compatibility. Reasons distinguish unavailable models/calibration, failed release gates, and low-confidence/high-entropy classification. Uncertain predictions never initiate automatic blocking or rate-limiting, including when an experimental anomaly score is elevated. A prior accepted-attack action can still cover later packets on the same connection until it expires or a new TCP session begins.

**Pause on threat** optionally pauses the visualization exactly at an accepted attack verdict. Resume continues past that verdict. Pausing playback is not network enforcement. Seeking, restarting, looping and changing response mode deterministically recompute the counterfactual view without changing the original model predictions.

The app retains predictions computed from the original complete input, even for packets that a simulated policy would have dropped. It does not claim that downstream inference has been rerun on a genuinely filtered network stream. Logs and exports identify this scope. Real prevention would require a separately authorized and validated inline/firewall integration.

## Reference continuations

Known botnet/DDoS virtual scenarios include explicitly labeled **repeated reference continuation** packets. A non-SYN packet from each eligible reference session is repeated to complete a 16-packet context and add 16 subsequent packets, so the demo can show post-verdict drops. No new attack packets are transmitted. Original uploaded captures and the unseen challenge are unchanged. Labels do not enter inference; the active model scores the resulting virtual capture normally. The synthetic context can change predictions and behavioral features, so virtual-scenario scores must never be presented as accuracy evidence.

The source note and API expose original/repeated counts per phase, total repetitions and a content digest. These replace the earlier reference-only simulation counts:

| Scenario | Total packets | Explicit repeated packets | Accepted botnet / DDoS / uncertain flows |
|---|---:|---:|---|
| Mixed | 2,634 | 1,615 | 1 / 25 / 48 |
| DDoS | 1,620 | 768 | 0 / 25 / 20 |
| Botnet | 1,588 | 847 | 1 / 0 / 14 |
| Unseen | 916 | 0 | 0 / 0 / 45 |

These are local demonstration outcomes, not guaranteed recognition on other traffic.

## Behavioral models

`flow-behavior-v1` adds 18 identity-independent features: packet count, bytes, duration, mean/variation of packet size and interarrival time, direction fraction, TCP SYN/ACK/RST fractions, one-second destination packet/byte/connection/sender counts and protocol indicators. Context uses at most 128 recent packets per connection, 8,192 connection entries and 100,000 rolling-window events. Snapshots are taken when flow context becomes available, not after reading the remainder of a capture. IPs and ports serve as aggregation keys but are not model inputs.

Two CPU models were trained: a class-balanced random forest classifier and a normal-only Isolation Forest. A versioned JSON tree format is used instead of pickle deserialization; its scores were checked against sklearn. The GPU byte classifier remains active and unchanged. Flow inspection shows the behavioral suggestion, its uncalibrated score, anomaly score/threshold and destination context. Behavioral evidence never overrides the primary verdict or enables blocking. Missing or invalid behavioral artifacts degrade to unavailable evidence while the byte classifier continues.

Training used **20,231 labeled flow contexts** from source-designated training captures. Normal-only fitting used 3,223 real normal contexts. The CTU-Normal-7 training prefix was expanded from 16 MiB/67 previously available independent contexts to 64 MiB/223 contexts. [Publisher provenance](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-7/).

A new complete [CTU-Normal-9 browsing capture](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-9/) was reserved for testing: 926 frames, 86 supported flow contexts. Its original relative timestamps were preserved exactly; no absolute-time label joins or timestamp repair were performed. No source is shared across train and validation/test/challenge partitions. Threshold selection uses only validation-normal scores: the maximum per-source 99th percentile. The inspected HOIC capture is a challenge, not a new untouched test.

## Evaluation outcome

The behavioral models **failed promotion checks** and remain advisory. The classifier recognized all 6,000 inspected HOIC challenge contexts, but its accepted attack rate on the fresh normal browsing source was 26.74%; attack recall on CTU-10 was 6.45%, and on Friday 20.66%. Normal anomaly rate on the fresh browsing source was 4.65%; the novelty detector flagged none of the inspected HOIC contexts. Thus a high HOIC classifier score is not evidence that the entire behavioral system is reliable.

Full source-specific metrics, capture hashes, data partitions, limitations, promotion gates and the behavioral artifact digest are in [behavior-evaluation.json](validation/behavior-evaluation.json). The UI foregrounds these failed checks. No improved overall accuracy or production-ready unseen-attack detection is claimed. Further promotion needs diverse independent normal and attack sources, frozen validation selection, per-source false-alert/recall limits and an independent audit. The new browsing test is now inspected and must not be reused as an untouched test after tuning.

## Reproduce

With the existing acquired and labeled corpora available:

```text
python -m scripts.acquire_behavior_data
python -m ml.train_behavior
node --test tests/stream.test.cjs tests/stream-ui.test.cjs
python -m pytest -q
python -m scripts.gpu_container image
python -m scripts.review_app start --recreate
```

The trained artifact is local at `ml/checkpoints/behavior_detector.json`, covered by the existing checkpoint mount and included in newly generated review bundles when available. Model files and raw captures remain outside Git; reproducible code and evaluation reports are committed. CPU training is appropriate for these small tree models; no byte-model GPU retraining or 24-hour longevity run was started. The byte-model CPU/GPU speed comparison excludes behavioral processing; current capture telemetry separately reports `behavior_ms` and total `analysis_ms`.

Regression checks cover causal feature snapshots, address-identity invariance, packets beyond the first-16 context, advisory fallback, uncertainty reasons, policy boundaries, bidirectional matching, decision-time ordering, expiry, new TCP sessions, fixed-window rate limiting, pause/resume and deterministic replay. GPU HTTP/controller checks exercise all four scenarios and inspect their evidence. Browser visual verification remains pending because local browser automation is disabled.

Final verification: 33 backend tests passed; one native-extension check was skipped on Windows. All 19 frontend/controller tests passed with a real GPU response and model dashboard data; the other three GPU scenarios also passed controller replay checks. At completion, Mixed simulated blocking drops 896 of 2,634 recorded/synthetic packets and the rate-limit policy drops 741. DDoS drops 400/275; Botnet drops 496/466; Unseen drops 0/0 (blocking/rate-limit respectively). Monitor mode drops zero. These are deterministic counterfactual counts, not measured prevention on a real network.
