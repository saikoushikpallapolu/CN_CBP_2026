# Review TrafficScan

Open **http://127.0.0.1:8000**. The local GPU service is running.

The main screen is now **Traffic stream**. Connect **192.0.2.10** to watch a virtual normal/attack sequence, or upload a capture for timestamped playback. See [the stream/simulation guide](STREAM_SIMULATION.md). This is replay, not a live network connection.

For a presentation, use **Traffic stream → Connect sensor**, then show **Packet & threat log** and **Model & validation**. See [the four-minute demo guide](DEMO_GUIDE.md) and [the latest improvement experiments](MODEL_IMPROVEMENT_RESULTS.md).

1. Choose **CSE 2018 · LOIC attack window** for a real malicious reference, or **Monday · normal baseline** for normal traffic. Friday contains mixed traffic; its name does not determine predictions.
2. Inspect a flow for sanitized grayscale/hex evidence and class scores.
3. Search/filter the table, export JSON/CSV, and reopen saved investigations from **Capture history**.
4. Open **Model & validation** for active TensorRT measurements and unresolved release gates.

Review predictions are explicitly experimental. Production readiness remains false. HOIC is escalated as UNKNOWN rather than identified by attack type. See [the final measured report](FINAL_REVIEW_REPORT.md).

## Service controls

```text
python -m scripts.review_app start
python -m scripts.review_app status
python -m scripts.review_app stop
```

Docker Desktop must be running. History lives in `artifacts/review/`. `start --recreate` refreshes only the labeled review container and preserves history. The service is localhost-only; public deployment uses the separate authenticated, release-gated configuration.

## Review archive

`artifacts/release/trafficscan-review.zip` includes source, checkpoints, ONNX/INT8 graphs, the RTX-specific TensorRT engine, frozen training tensors, reference captures and evidence. `REVIEW_MANIFEST.json` contains per-file hashes. Raw corpora, credentials, private history, Python environments and NVIDIA libraries are excluded.

On a fresh machine, install dependencies and build the documented Docker images first. Rebuild TensorRT for a different GPU/runtime. See [GPU deployment](GPU_DEPLOYMENT.md) and [Kaggle training](KAGGLE_GPU.md).

The longevity replay was stopped at the user's request after approximately 48 minutes and 5,970 analyses without recorded inference errors. No full-duration pass is claimed; it has not been restarted. A presentation does not require a 24-hour replay.
