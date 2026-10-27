"""Audit float32 and INT8 exported models on the source-held-out test partition."""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import onnxruntime as ort
from sklearn.metrics import accuracy_score, f1_score


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/production/dataset.npz")
    parser.add_argument("--checkpoint", default="ml/checkpoints/flow_resnet.pth")
    parser.add_argument("--models", nargs="+", default=["ml/checkpoints/flow_resnet.onnx", "ml/checkpoints/flow_resnet.int8.onnx"])
    parser.add_argument("--output", default="artifacts/export-test-audit.json")
    args = parser.parse_args()
    dataset = np.load(args.data, allow_pickle=False)
    mask = dataset["split"] == "test"
    x = dataset["x"][mask].astype(np.float32).reshape(-1, 1, 512) / 127.5 - 1
    y = dataset["y"][mask]
    packets = dataset["packets"][mask]
    checksum = hashlib.sha256(Path(args.checkpoint).read_bytes()).hexdigest()
    report = dict(test_samples=len(y), test_sources=sorted(map(str, set(dataset["source"][mask]))), models={})
    reference = None
    for path in args.models:
        options = ort.SessionOptions()
        options.intra_op_num_threads, options.inter_op_num_threads = 2, 1
        session = ort.InferenceSession(path, sess_options=options, providers=["CPUExecutionProvider"])
        metadata = session.get_modelmeta().custom_metadata_map
        if metadata.get("checkpoint_sha256") != checksum:
            raise ValueError("Export/checkpoint identity mismatch")
        logits = np.concatenate([session.run(None, {"bytes": x[i:i + 64]})[0] for i in range(0, len(x), 64)])
        scores = logits / float(metadata["temperature"])
        scores = np.exp(scores - scores.max(axis=1, keepdims=True))
        p = scores / scores.sum(axis=1, keepdims=True)
        prediction = p.argmax(1)
        confidence = p.max(1)
        entropy = -(p * np.log(np.maximum(p, 1e-12))).sum(1) / np.log(3)
        rejected = (confidence < .75) | (entropy > .8)
        ece = 0.
        for index in range(10):
            selected = (confidence >= index / 10) & ((confidence < (index + 1) / 10) if index < 9 else confidence <= 1)
            if selected.any():
                ece += selected.mean() * abs((prediction[selected] == y[selected]).mean() - confidence[selected].mean())
        benign = y == 0
        escalation = (prediction != 0) | rejected
        metrics = dict(accuracy=float(accuracy_score(y, prediction)), macro_f1=float(f1_score(y, prediction, labels=[0, 1, 2], average="macro", zero_division=0)),
                       packet_weighted_accuracy=float(np.average(prediction == y, weights=packets)),
                       benign_packet_escalation_rate=float(np.average(escalation[benign], weights=packets[benign])),
                       rejection_rate=float(rejected.mean()), expected_calibration_error=float(ece), temperature=float(metadata["temperature"]))
        if reference is None:
            reference = prediction
        metrics["agreement_with_float32"] = float((prediction == reference).mean())
        report["models"][Path(path).name] = metrics
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
