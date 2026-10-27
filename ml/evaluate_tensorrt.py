"""Measure actual CUDA/TensorRT parity and synchronized model batch latency."""
import argparse
import hashlib
import json
import time
from pathlib import Path
import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score
from classification.tensorrt_backend import TensorRTBackend
from ml.production_model import FlowResNet, probabilities, calibrate_temperature


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", default="ml/checkpoints/flow_resnet.pth")
    parser.add_argument("--engine", default="ml/checkpoints/flow_resnet.engine")
    parser.add_argument("--data", default="data/production/dataset.npz")
    parser.add_argument("--output", default="artifacts/tensorrt-audit.json")
    parser.add_argument("--cuda-python", action="store_true", help="Pinned CPU staging with CUDA Python; CPU Torch reference")
    args = parser.parse_args()
    if not args.cuda_python and not torch.cuda.is_available():
        raise SystemExit("CUDA runtime unavailable; no GPU measurements produced")
    torch.set_num_threads(2)
    checkpoint = torch.load(args.checkpoint, map_location="cpu", weights_only=True)
    reference_device = "cpu" if args.cuda_python else "cuda"
    model = FlowResNet().to(reference_device).eval()
    model.load_state_dict(checkpoint["model_state_dict"])
    if args.cuda_python:
        from classification.tensorrt_cuda_backend import TensorRTCudaBackend
        backend = TensorRTCudaBackend(args.engine, args.checkpoint)
    else:
        backend = TensorRTBackend(args.engine, args.checkpoint)
    data = np.load(args.data, allow_pickle=False)
    validation = data["split"] == "validation"
    validation_x = torch.from_numpy(data["x"][validation].astype(np.float32).reshape(-1, 1, 512) / 127.5 - 1)
    validation_y = torch.from_numpy(data["y"][validation].copy()).long()
    if set(validation_y.tolist()) != {0, 1, 2}:
        raise ValueError("TensorRT calibration requires all validation classes")
    with torch.inference_mode():
        validation_logits = torch.cat([backend(validation_x[start:start + 64].to(reference_device)).cpu()
                                       for start in range(0, len(validation_x), 64)])
    backend.metadata.update(temperature=str(calibrate_temperature(validation_logits, validation_y)),
                            calibration_backend="tensorrt", calibration_samples=len(validation_y),
                            calibration_dataset_sha256=hashlib.sha256(Path(args.data).read_bytes()).hexdigest())
    Path(args.engine).with_suffix(".json").write_text(json.dumps(backend.metadata, indent=2))
    mask = data["split"] == "test"
    x = torch.from_numpy(data["x"][mask].astype(np.float32).reshape(-1, 1, 512) / 127.5 - 1)
    y, packet_counts = data["y"][mask], data["packets"][mask]
    float_logits, accelerated_logits = [], []
    with torch.inference_mode():
        for start in range(0, len(x), 64):
            tensor = x[start:start + 64].to(reference_device)
            float_logits.append(model(tensor).cpu())
            accelerated_logits.append(backend(tensor).cpu())
        reference, actual = torch.cat(float_logits), torch.cat(accelerated_logits)
        p, entropy, rejected = probabilities(actual, float(backend.metadata["temperature"]))
        prediction = p.argmax(1).numpy()
        probe = torch.zeros(64, 1, 512, device=reference_device)
        timings = {}
        for name, runner in (("pytorch_" + reference_device, model), ("tensorrt", backend)):
            for _ in range(20):
                runner(probe)
            samples = []
            for _ in range(100):
                if not args.cuda_python:
                    torch.cuda.synchronize()
                start = time.perf_counter()
                runner(probe)
                if not args.cuda_python:
                    torch.cuda.synchronize()
                samples.append((time.perf_counter() - start) * 1000)
            timings[name] = dict(batch64_p50_ms=float(np.median(samples)), batch64_p95_ms=float(np.percentile(samples, 95)))
    benign = y == 0
    escalation = (prediction != 0) | rejected.numpy()
    confidence = p.max(1).values.numpy()
    ece = 0.
    for index in range(10):
        selected = (confidence >= index / 10) & ((confidence < (index + 1) / 10) if index < 9 else confidence <= 1)
        if selected.any():
            ece += selected.mean() * abs((prediction[selected] == y[selected]).mean() - confidence[selected].mean())
    report = dict(gpu=backend.metadata["gpu"], cuda=torch.version.cuda, torch=str(torch.__version__),
                  provider="cuda-python pinned staging" if args.cuda_python else "torch CUDA buffers",
                  engine_metadata=backend.metadata, checkpoint_sha256=hashlib.sha256(Path(args.checkpoint).read_bytes()).hexdigest(),
                  scope="Synchronized 64-flow inference; CUDA Python includes host/device transfers; excludes ingestion and flow context waiting",
                  timings=timings, test_samples=len(y),
                  agreement_with_float32=float((prediction == reference.argmax(1).numpy()).mean()),
                  max_logit_error=float((reference - actual).abs().max()),
                  expected_calibration_error=float(ece),
                  accuracy=float(accuracy_score(y, prediction)),
                  macro_f1=float(f1_score(y, prediction, labels=[0, 1, 2], average="macro", zero_division=0)),
                  packet_weighted_accuracy=float(np.average(prediction == y, weights=packet_counts)),
                  benign_packet_escalation_rate=float(np.average(escalation[benign], weights=packet_counts[benign])),
                  rejection_rate=float(rejected.float().mean()))
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
