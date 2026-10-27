"""Frozen-engine evaluation of a new attack subset; no calibration or fitting."""
import argparse
import json
from pathlib import Path
import numpy as np
import torch
from classification.tensorrt_cuda_backend import TensorRTCudaBackend
from data_processing.production import REPRESENTATION
from ml.production_model import probabilities


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--origin", default="cse21-hoic")
    parser.add_argument("--output", default="artifacts/additional-attack-gpu.json")
    args = parser.parse_args()
    torch.set_num_threads(2)
    data = np.load(args.data, allow_pickle=False)
    if str(data["representation"]) != REPRESENTATION or "origin" not in data:
        raise ValueError("A versioned dataset with prepared-subset provenance is required")
    mask = (data["split"] == "validation") & (data["origin"] == args.origin)
    if not mask.any() or not np.all(data["y"][mask] > 0):
        raise ValueError("Expected a nonempty independently labeled attack-validation subset")
    backend = TensorRTCudaBackend(args.engine, args.checkpoint)
    x = torch.from_numpy(data["x"][mask].astype(np.float32).reshape(-1, 1, 512) / 127.5 - 1)
    predicted, rejected = [], []
    with torch.inference_mode():
        for start in range(0, len(x), 64):
            p, entropy, r = probabilities(backend(x[start:start + 64]), float(backend.metadata["temperature"]))
            predicted.extend(p.argmax(1).tolist())
            rejected.extend(r.tolist())
    predicted, rejected = np.array(predicted), np.array(rejected)
    benign = (predicted == 0) & ~rejected
    report = dict(origin=args.origin, samples=len(x), source_groups=sorted(map(str, set(data["source"][mask]))),
                  scope="Frozen TensorRT engine on additional published endpoint/time attack windows; no refitting",
                  checkpoint_sha256=backend.metadata["checkpoint_sha256"], engine_sha256=backend.metadata["engine_sha256"],
                  temperature=float(backend.metadata["temperature"]),
                  known_class_accuracy=float((predicted == data["y"][mask]).mean()),
                  unknown_rate=float(rejected.mean()), attack_escalation_rate=float((~benign).mean()),
                  accepted_benign_rate=float(benign.mean()),
                  limitation="Attack-only subset: no benign false-positive rate can be inferred")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
