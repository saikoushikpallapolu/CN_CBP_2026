# Recorded validation evidence

These are bounded local research measurements, not enterprise certification.

- `model-comparison.json`: preserved baseline versus expanded GPU candidate.
- `identity_audit.json`: real-packet identity-mutation invariance audit.
- `deployment-smoke.json`: hardened CPU container HTTP checks.
- `export-test-audit.json`: older baseline ONNX/INT8 audit.
- `candidate-export-test-audit.json`: candidate export audit captured before the TensorRT floating-point-bias compatibility change; its symmetric-graph entry must not be assumed to describe the current graph.
- `tensorrt-audit.json`: actual Linux GPU execution of the corrected symmetric INT8 graph, using its ONNX-validation-fitted temperature. Engine-specific temperature refitting was subsequently implemented but not rerun before work stopped.
- `replay-recovery-smoke.summary.json`: short smoke test of the repaired audit logger; not a 24-hour result.
- `dashboard.png`: reviewed UI screenshot from the earlier baseline session; current local weights use the expanded candidate.

The final archive CRC/HOIC acquisition, accelerated capture benchmark, full-duration replay and enterprise release gates remain unfinished. The handoff at the top of `../PRODUCTION_IMPLEMENTATION_STATUS.md` is authoritative for stopped/running status.
