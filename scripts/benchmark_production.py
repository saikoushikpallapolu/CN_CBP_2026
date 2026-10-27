"""Reproducible end-to-end capture benchmark; never projects NIC line rate."""
import argparse
import json
import time
from pathlib import Path
import numpy as np
from classification.production import FlowClassifier


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("capture")
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", default="artifacts/benchmark.json")
    args = parser.parse_args()
    classifier = FlowClassifier()
    if not classifier.model:
        raise SystemExit("A trained checkpoint is required for inference benchmarking")
    classifier.analyze(args.capture, Path(args.capture).name)
    measurements = []
    for _ in range(args.repeats):
        result = classifier.analyze(args.capture, Path(args.capture).name)
        measurements.append(result["telemetry"])
    report = dict(model=classifier.health(), runs=measurements,
                  analysis_p50_ms=float(np.median([r["analysis_ms"] for r in measurements])),
                  analysis_p95_ms=float(np.percentile([r["analysis_ms"] for r in measurements], 95)),
                  median_packets_per_second=float(np.median([r["packets_per_second"] for r in measurements])))
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(json.dumps({key: value for key, value in report.items() if key not in ("model", "runs")}, indent=2))


if __name__ == "__main__":
    main()
