# Recorded validation evidence

Current review evidence is described in [FINAL_REVIEW_REPORT.md](../FINAL_REVIEW_REPORT.md). The `final-*` JSON files and `hoic-gpu-audit.json` supersede the older baseline/partial validation records below. `review-dashboard.png` and `review-model.png` show the current GPU review app. A live 24-hour audit remains incomplete until its duration actually elapses.

These are bounded local research measurements, not enterprise certification.

- `model-comparison.json`: preserved baseline versus expanded GPU candidate.
- `identity_audit.json`: real-packet identity-mutation invariance audit.
- `deployment-smoke.json`: hardened CPU container HTTP checks.
- `export-test-audit.json`: older baseline ONNX/INT8 audit.
- `candidate-export-test-audit.json`: candidate export audit captured before the TensorRT floating-point-bias compatibility change; its symmetric-graph entry must not be assumed to describe the current graph.
- `tensorrt-audit.json`: actual Linux GPU execution of the corrected symmetric INT8 graph, using its ONNX-validation-fitted temperature. Engine-specific temperature refitting was subsequently implemented but not rerun before work stopped.
- `replay-recovery-smoke.summary.json`: short smoke test of the repaired audit logger; not a 24-hour result.
- `dashboard.png`: reviewed UI screenshot from the earlier baseline session; current local weights use the expanded candidate.

Full archive CRC/HOIC acquisition, the accelerated capture benchmark and GPU HTTP checks are complete. The full-duration replay and enterprise release gates remain pending. [FINAL_REVIEW_REPORT.md](../FINAL_REVIEW_REPORT.md) is authoritative for current status.
