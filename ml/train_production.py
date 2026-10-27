"""Source-separated training, calibration, untouched test evaluation and sign-off."""
import argparse
import copy
import json
import random
import time
import platform
import hashlib
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, precision_recall_fscore_support
from torch.utils.data import DataLoader, TensorDataset

from data_processing.production import REPRESENTATION
from ml.production_model import FlowResNet, FocalLoss, calibrate_temperature, probabilities

CLASSES = ["benign", "botnet", "ddos"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/production/dataset.npz")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--output", default="ml/checkpoints/flow_resnet.pth")
    parser.add_argument("--identity-audit", default="artifacts/identity_audit.json")
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    args = parser.parse_args()
    if args.epochs <= 0 or args.batch_size <= 0 or args.threads <= 0:
        parser.error("epochs, batch-size and threads must be positive")
    torch.set_num_threads(args.threads)
    random.seed(42)
    np.random.seed(42)
    torch.manual_seed(42)
    data = np.load(args.data, allow_pickle=False)
    if str(data["representation"]) != REPRESENTATION:
        raise ValueError("Dataset representation mismatch")
    split, source = data["split"], data["source"]
    names = ["train", "validation", "test"]
    for a in names:
        for b in names:
            if a != b and set(source[split == a]) & set(source[split == b]):
                raise ValueError("Source leakage between splits")
    partitions = {}
    for name in names:
        mask = split == name
        if not mask.any():
            raise ValueError(f"Missing independent {name} data")
        partitions[name] = TensorDataset(torch.from_numpy(data["x"][mask].copy()).float().reshape(-1, 1, 512) / 127.5 - 1,
                                         torch.from_numpy(data["y"][mask]).long())
    if set(partitions["train"].tensors[1].tolist()) != {0, 1, 2}:
        raise ValueError("Training requires verified examples of every class")
    device = torch.device(("cuda" if torch.cuda.is_available() else "cpu") if args.device == "auto" else args.device)
    if device.type == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA was explicitly requested but is unavailable")
    training_start = time.perf_counter()
    model = FlowResNet().to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=.001, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, args.epochs)
    counts = torch.bincount(partitions["train"].tensors[1], minlength=3).float()
    loss_fn = FocalLoss(weight=(counts.sum() / (3 * counts.clamp_min(1))).to(device))
    loaders = {name: DataLoader(value, batch_size=args.batch_size, shuffle=name == "train") for name, value in partitions.items()}

    def infer(name):
        model.eval()
        outputs, targets = [], []
        with torch.inference_mode():
            for x, y in loaders[name]:
                outputs.append(model(x.to(device)).cpu())
                targets.append(y)
        return torch.cat(outputs), torch.cat(targets)

    best, state, stale, history = float("inf"), None, 0, []
    for epoch in range(args.epochs):
        model.train()
        total = 0
        for x, y in loaders["train"]:
            optimizer.zero_grad(set_to_none=True)
            loss = loss_fn(model(x.to(device)), y.to(device))
            loss.backward()
            optimizer.step()
            total += float(loss.detach())
        scheduler.step()
        logits, target = infer("validation")
        per_flow = torch.nn.functional.cross_entropy(logits, target, reduction="none")
        validation_loss = float(torch.stack([per_flow[target == label].mean()
                                            for label in target.unique()]).mean())
        history.append(dict(epoch=epoch + 1, train_loss=total / len(loaders["train"]), validation_loss=validation_loss))
        print(history[-1], flush=True)
        if validation_loss < best:
            best, state, stale = validation_loss, copy.deepcopy(model.state_dict()), 0
        else:
            stale += 1
        if stale >= 7:
            break
    model.load_state_dict(state)
    logits, target = infer("validation")
    temperature = calibrate_temperature(logits, target)
    test_logits, test_target = infer("test")
    p, entropy, rejected = probabilities(test_logits, temperature)
    calibration_valid = set(partitions["validation"].tensors[1].tolist()) == {0, 1, 2}
    experimental_rejection_rate = float(rejected.float().mean())
    if not calibration_valid:
        rejected[:] = True
    pred = p.argmax(1)
    confidence = p.max(1).values
    calibration_error = 0.
    for index in range(10):
        selected = (confidence >= index / 10) & (confidence <= 1 if index == 9 else confidence < (index + 1) / 10)
        if selected.any():
            calibration_error += float(selected.float().mean()) * abs(float((pred[selected] == test_target[selected]).float().mean()) - float(confidence[selected].mean()))
    benign = test_target == 0
    # UNKNOWN benign flows count as escalations, so rejection cannot hide FPs.
    false_positive = float(((pred[benign] != 0) | rejected[benign]).float().mean()) if benign.any() else None
    packet_counts = data["packets"] if "packets" in data else np.any(data["x"] != 0, axis=2).sum(axis=1)
    test_packets = torch.from_numpy(packet_counts[split == "test"].copy()).float()
    escalated = (pred != 0) | rejected
    benign_packet_rate = float((test_packets[benign] * escalated[benign]).sum() / test_packets[benign].sum()) if benign.any() else None
    packet_accuracy = float((test_packets * (pred == test_target)).sum() / test_packets.sum())
    model.eval()
    probe = torch.zeros(64, 1, 512, device=device)
    with torch.inference_mode():
        for _ in range(5):
            model(probe)
        timings = []
        for _ in range(30):
            if device.type == "cuda":
                torch.cuda.synchronize()
            start = time.perf_counter()
            model(probe)
            if device.type == "cuda":
                torch.cuda.synchronize()
            timings.append((time.perf_counter() - start) * 1000)
    accuracy = float(accuracy_score(test_target, pred))
    macro = float(f1_score(test_target, pred, labels=[0, 1, 2], average="macro", zero_division=0))
    coverage = {name: sorted(set(value.tensors[1].tolist())) for name, value in partitions.items()}
    report = dict(accuracy=accuracy, macro_f1=macro, benign_escalation_rate=false_positive,
                  expected_calibration_error=calibration_error,
                  packet_weighted_accuracy=packet_accuracy, benign_packet_escalation_rate=benign_packet_rate,
                  metric_unit="flow burst; packet-weighted metrics count only packets represented in these bursts, not all raw-capture packets",
                  experimental_rejection_rate=experimental_rejection_rate,
                  rejection_rate=float(rejected.float().mean()), accepted_accuracy=float((pred[~rejected] == test_target[~rejected]).float().mean()) if (~rejected).any() else None,
                  confusion_matrix=confusion_matrix(test_target, pred, labels=[0, 1, 2]).tolist(),
                  temperature=temperature, batch64_p50_ms=float(np.median(timings)), batch64_p95_ms=float(np.percentile(timings, 95)),
                  device=str(device), validation_objective="mean classwise cross entropy", coverage=coverage, samples={name: len(value) for name, value in partitions.items()},
                  sources={name: sorted(set(source[split == name])) for name in names}, history=history,
                  limitations=["CIC Wednesday DoS is grouped with DDoS", "Subsets do not establish population-wide performance", "Temperature/entropy rejection does not guarantee zero-day detection"])
    audit_path = Path(args.identity_audit)
    audit = json.loads(audit_path.read_text()) if audit_path.exists() else {}
    report["identity_audit"] = audit
    report["calibration_valid"] = calibration_valid
    report["class_counts"] = {name: torch.bincount(value.tensors[1], minlength=3).tolist() for name, value in partitions.items()}
    precision, recall, f1, support = precision_recall_fscore_support(test_target, pred, labels=[0, 1, 2], zero_division=0)
    report["per_class"] = {label: dict(precision=float(precision[index]), recall=float(recall[index]),
                                     f1=float(f1[index]), support=int(support[index])) for index, label in enumerate(CLASSES)}
    report["training_sources_per_class"] = {CLASSES[index]: sorted(set(source[(split == "train") & (data["y"] == index)])) for index in range(3)}
    report["environment"] = dict(python=platform.python_version(), torch=str(torch.__version__), numpy=np.__version__)
    report["environment"]["gpu"] = torch.cuda.get_device_name() if device.type == "cuda" else None
    report["environment"]["cuda"] = torch.version.cuda
    report["peak_cuda_allocated_bytes"] = torch.cuda.max_memory_allocated() if device.type == "cuda" else None
    report["training_and_evaluation_seconds"] = time.perf_counter() - training_start
    with Path(args.data).open("rb") as dataset_file:
        report["dataset_sha256"] = hashlib.file_digest(dataset_file, "sha256").hexdigest()
    report["latency_scope"] = "Model-only batch of 64 flow bursts; excludes ingestion and waiting for flow context"
    gates = dict(accuracy=accuracy > .95 and packet_accuracy > .95, macro_f1=macro > .94, benign_fpr=benign_packet_rate is not None and benign_packet_rate < .001,
                 model_batch_latency=report["batch64_p95_ms"] < 5, end_to_end_latency=False,
                 class_coverage=all(value == [0, 1, 2] for value in coverage.values()),
                 calibration_coverage=report["calibration_valid"],
                 calibration_reliability=calibration_valid and calibration_error < .05,
                 training_sample_size=min(report["class_counts"]["train"]) >= 1400,
                 training_source_diversity=all(len(sources) >= 2 for sources in report["training_sources_per_class"].values()),
                 identity_invariance=audit.get("representation") == REPRESENTATION and audit.get("exact_tensor_invariance", False) and audit.get("checked", 0) >= 1000,
                 stability_24h=False, independent_enterprise_audit=False)
    report["gates"] = gates
    report["calibration_validated"] = gates["calibration_reliability"]
    report["production_ready"] = all(gates.values())
    # NumPy string/scalar metadata is JSON-compatible but not weights_only-safe
    # under torch.load. Normalize report metadata to built-in Python types.
    report = json.loads(json.dumps(report, allow_nan=False))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    temporary = out.with_suffix(".pth.tmp")
    torch.save(dict(architecture="flow_resnet18_1d", representation=REPRESENTATION, model_state_dict=model.cpu().state_dict(),
                    classes=CLASSES, temperature=temperature, confidence_threshold=.75, entropy_threshold=.8,
                    report=report), temporary)
    # Verify the serving loader can read it before replacing an existing model.
    torch.load(temporary, map_location="cpu", weights_only=True)
    temporary.replace(out)
    out.with_suffix(".json").write_text(json.dumps(report, indent=2, allow_nan=False))
    print(json.dumps({k: v for k, v in report.items() if k != "history"}, indent=2))


if __name__ == "__main__":
    main()
