# Test and demonstrate TrafficScan

Open http://127.0.0.1:8000 and choose **Test & demo → Run demo suite**. This runs the actual active model on four small public recorded captures, then compares predictions with separately stored labels. No live laptop traffic is captured. No verdict is selected from a filename or injected for presentation.

## A four-minute presentation

1. **Explain the input:** “We inspect saved network traffic, group the first 16 packets of a connection, mask identifying fields, and create a byte fingerprint.” This is an offline demonstration of the GPU pipeline.
2. **Run Test & demo:** Show each case's exact-class match, UNKNOWN rate and attack escalation. Explain that correctly naming an attack and sending unknown traffic for review are different outcomes.
3. **Inspect known LOIC:** Click **Inspect capture**, open a flow, and show its fingerprint, hex preview and class scores. This is a known training-source reference, not independent accuracy evidence.
4. **Inspect unseen HOIC:** It is escalated as UNKNOWN. Say: “The model cannot reliably identify this attack family; it sends it for review.” Do not call UNKNOWN a correct DDoS prediction.
5. **Show normal and botnet results:** Discuss missed recognition and false alerts honestly. Export the demo report, then open a saved investigation from Capture history.
6. **Show Model & validation:** Explain the limited held-out results and failed release gates. The app is experimental. It is not blocking or forwarding live network packets.

## Recorded small-demo results

The first label-consistent bursts are selected without looking at model predictions. Results below describe the unchanged TensorRT model, not guaranteed performance on other traffic.

| Case | Flows | Exact class | UNKNOWN | Interpretation |
|---|---:|---:|---:|---|
| Controlled normal, CTU scenario 9 | 32 | 75.0% | 25.0% | Review burden remains; no attack verdicts in this small sample |
| Botnet, CTU scenario 10 | 31 | 51.6% | 48.4% | All escalated; only about half identified as botnet |
| Known LOIC, CSE 20 February | 32 | 100.0% | 0.0% | Training-source workflow example, not a benchmark |
| Unseen HOIC, CSE 21 February | 32 | 0.0% | 100.0% | Rejection/escalation works; type recognition fails |

The suite is intentionally small and does not replace the full source-separated evaluation. Mixed original Friday samples may contain normal flows even during an attack window; do not infer truth from the capture name.

## Reproduce the demo and test the app

```powershell
python -m scripts.prepare_demo
python -m scripts.review_app start
python -m scripts.test_demo --verify-upload
python -m pytest -q
```

Use `TRAFFICSCAN_API_KEY` when testing an authenticated deployment. The API command saves `artifacts/demo-report.json`. Its upload check sends the same attack capture under `totally-normal-traffic.pcap` and verifies that verdicts and fingerprints match. This demonstrates content-based inference, not filename labeling. The malformed upload, authorization, backpressure and UNKNOWN-accounting cases are covered by automated tests.

To inspect your own authorized saved capture, upload a `.pcap` or `.pcapng` within the displayed limits. That shows the app's predictions; it does not measure accuracy unless someone independently labels the traffic first. Measure exact-class precision/recall, attack escalation, benign attack alerts and benign UNKNOWN separately. Never use the same capture in training and evaluation.

## Understand the metrics

- **Exact class:** Correct accepted class; UNKNOWN never counts as correct recognition.
- **False attack alerts:** Normal traffic accepted as botnet or DDoS.
- **Benign review rate:** False attack alerts plus normal traffic sent to UNKNOWN.
- **Attack escalation:** Attack traffic either identified as an attack or sent to UNKNOWN. This is not attack-type accuracy.

No 24-hour run is required for a presentation. The earlier longevity replay was stopped at the user's request after 5,970 analyses and approximately 48 minutes without recorded inference errors. It has not been restarted.
