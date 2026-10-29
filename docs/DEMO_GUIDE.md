# Test and demonstrate TrafficScan

Open http://127.0.0.1:8000 and choose **Traffic stream**. Keep `192.0.2.10`, choose a scenario and click **Connect sensor**. The active model analyzes recorded public frames before replay. No live laptop traffic is captured. The former Test & demo tab has been removed; the separate labeled comparison suite remains available through the CLI/API.

## Four-minute walkthrough

1. **Connect Mixed traffic:** Show the wave and counters advancing together. The source note identifies normal, botnet, known DDoS and unseen-attack references, counts and the content checksum.
2. **Show Packet & threat log:** Each recorded packet has its own timestamp, sequence, protocol, length and endpoints. THREAT and REVIEW entries appear when a flow verdict is ready. Packet arrival alone is not an attack prediction.
3. **Pause and inspect:** Filter Threats or Review; click an event to inspect the flow. Seek backwards and show future events disappear. Export log saves all revealed matching events, including those outside the visible 200-row page.
4. **Change the scenario and reconnect:** DDoS, Botnet and Unseen attack use different reference combinations. The normal baseline is intentionally shared; these are repeatable recorded sequences, not fresh network traffic.
5. **Show Model & validation:** Show the CPU/GPU timing comparison, time saved per 64 flows, held-out accuracy, macro F1, review rates and pending gates. The model is experimental. Savings exclude parsing, logging and flow-context waiting.
6. **Upload or reopen:** Upload a capture or use Capture history. Older investigations lack complete packet logs; re-analyze their captures to get the new packet view.

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
