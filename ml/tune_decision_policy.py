"""Validation-only class-specific rejection selection, then frozen regression audit."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import numpy as np
import torch
from classification.tensorrt_cuda_backend import TensorRTCudaBackend
from ml.production_model import probabilities


def summarize(logits, labels, packets, temperature, confidence, entropy):
    p, e, rejected = probabilities(logits, temperature, confidence, entropy)
    predicted = p.argmax(1).numpy()
    reject = rejected.numpy()
    benign = labels == 0
    def rate(values, mask):
        return float(np.average(values[mask], weights=packets[mask]))
    return dict(benign_escalation=rate((predicted != 0) | reject, benign),
                false_attack_alerts=rate((predicted != 0) & ~reject, benign),
                benign_unknown=rate(reject, benign),
                attack_escalation=rate((predicted != 0) | reject, ~benign),
                correct_attack_type=rate((predicted == labels) & ~reject, ~benign))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--output", default="artifacts/decision-policy.json")
    args = parser.parse_args()
    torch.set_num_threads(2)
    data = np.load(args.data, allow_pickle=False)
    assert not set(data["source"][data["split"] == "validation"]) & set(data["source"][data["split"] == "test"])
    engine = TensorRTCudaBackend(args.engine, args.checkpoint)
    temperature = float(engine.metadata["temperature"])
    def infer(split):
        mask = data["split"] == split
        x = torch.from_numpy(data["x"][mask].astype(np.float32).reshape(-1, 1, 512) / 127.5 - 1)
        with torch.inference_mode():
            logits = torch.cat([engine(x[i:i + 64]) for i in range(0, len(x), 64)])
        return logits, data["y"][mask], data["packets"][mask]
    validation = infer("validation")
    baseline = summarize(*validation, temperature, .75, .8)
    candidates = []
    for benign_confidence, attack_confidence, benign_entropy in itertools.product((.5, .55, .6, .65, .7, .75), (.75, .85, .9, .95), (.8, .9, .95)):
        confidence = [benign_confidence, attack_confidence, attack_confidence]
        entropy = [benign_entropy, .8, .8]
        measured = summarize(*validation, temperature, confidence, entropy)
        if (measured["false_attack_alerts"] <= baseline["false_attack_alerts"]
                and measured["attack_escalation"] >= baseline["attack_escalation"] - .005
                and measured["correct_attack_type"] >= baseline["correct_attack_type"] - .005):
            candidates.append((measured["benign_escalation"], -measured["attack_escalation"], confidence, entropy, measured))
    best = min(candidates, key=lambda row: row[:2])
    confidence, entropy, selected = best[2:]
    regression = infer("test")
    old_test = summarize(*regression, temperature, .75, .8)
    new_test = summarize(*regression, temperature, confidence, entropy)
    report = dict(checkpoint_sha256=engine.metadata["checkpoint_sha256"], engine_sha256=engine.metadata["engine_sha256"],
                  temperature=temperature, confidence_thresholds=confidence, entropy_thresholds=entropy,
                  selected_on="validation only; minimize benign escalation under <=0.5 percentage point attack-recall loss",
                  baseline_validation=baseline, selected_validation=selected,
                  baseline_regression=old_test, selected_regression=new_test,
                  dataset_sha256=hashlib.sha256(Path(args.data).read_bytes()).hexdigest(),
                  limitation="Regression test previously inspected during research; new independent traffic needed for certification",
                  validated_improvement=(selected["benign_escalation"] < baseline["benign_escalation"]
                      and new_test["benign_escalation"] < old_test["benign_escalation"]
                      and new_test["false_attack_alerts"] <= old_test["false_attack_alerts"]
                      and new_test["attack_escalation"] >= old_test["attack_escalation"] - .005))
    Path(args.output).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
