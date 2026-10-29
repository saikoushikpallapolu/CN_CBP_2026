"""Train a bounded challenger; select with validation only, never test data.

One predeclared experiment: source/class-balanced sampling, smoothed CE and
partial-flow augmentation. The deployed model is preserved unless validated.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler
from sklearn.metrics import f1_score, confusion_matrix
from ml.production_model import FlowResNet, FocalLoss, probabilities
from data_processing.production import REPRESENTATION


def metrics(logits, labels, packets, temperature):
    p, entropy, rejected = probabilities(logits, temperature)
    pred = p.argmax(1)
    benign = labels == 0
    attack = ~benign
    weights = torch.as_tensor(packets).float()
    average = lambda values, mask: float((values[mask].float() * weights[mask]).sum() / weights[mask].sum()) if mask.any() else None
    return dict(accuracy=float((pred == labels).float().mean()),
                macro_f1=float(f1_score(labels, pred, labels=[0, 1, 2], average="macro", zero_division=0)),
                benign_attack_alert_rate=average((pred != 0) & ~rejected, benign),
                benign_unknown_rate=average(rejected, benign),
                benign_escalation_rate=average((pred != 0) | rejected, benign),
                attack_escalation_recall=average((pred != 0) | rejected, attack),
                known_attack_recall=average((pred == labels) & ~rejected, attack),
                confusion_matrix=confusion_matrix(labels, pred, labels=[0, 1, 2]).tolist())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/production/expanded_validation_dataset.npz")
    parser.add_argument("--baseline", default="ml/checkpoints/candidate_flow_resnet.pth")
    parser.add_argument("--output", default="ml/checkpoints/improved_flow_resnet.pth")
    parser.add_argument("--epochs", type=int, default=15)
    parser.add_argument("--recipe", choices=("balanced", "focal"), default="balanced")
    args = parser.parse_args()
    if args.epochs <= 0:
        parser.error("epochs must be positive")
    if Path(args.output).resolve() == Path(args.baseline).resolve():
        parser.error("Write a challenger to a separate checkpoint; preserve the baseline")
    torch.set_num_threads(4)
    torch.manual_seed(123)
    np.random.seed(123)
    if not torch.cuda.is_available():
        raise RuntimeError("Explicit CUDA experiment requires CUDA")
    data = np.load(args.data, allow_pickle=False)
    assert str(data["representation"]) == REPRESENTATION
    train, validation = data["split"] == "train", data["split"] == "validation"
    assert not set(data["source"][train]) & set(data["source"][validation])
    def tensors(mask):
        return (torch.from_numpy(data["x"][mask].copy()).float().reshape(-1, 1, 512) / 127.5 - 1,
                torch.from_numpy(data["y"][mask].copy()).long())
    tx, ty = tensors(train)
    vx, vy = tensors(validation)
    # Give each source within each class equal total training contribution.
    keys = [(int(y), str(s)) for y, s in zip(data["y"][train], data["source"][train])]
    counts = {key: keys.count(key) for key in set(keys)}
    sources_per_class = {label: len({source for y, source in counts if y == label}) for label in (0, 1, 2)}
    weights = torch.tensor([1 / (counts[key] * sources_per_class[key[0]]) for key in keys], dtype=torch.double)
    sampler = WeightedRandomSampler(weights, len(tx), replacement=True)
    loader = DataLoader(TensorDataset(tx, ty), batch_size=64, sampler=sampler)
    if args.recipe == "focal":
        loader = DataLoader(TensorDataset(tx, ty), batch_size=64, shuffle=True)
    class_counts = torch.bincount(ty, minlength=3).float()
    focal = FocalLoss(weight=(class_counts.sum() / (3 * class_counts)).cuda())
    validation_keys = np.array([f"{int(y)}:{s}" for y, s in zip(data["y"][validation], data["source"][validation])])
    masks = [torch.from_numpy(validation_keys == key) for key in sorted(set(validation_keys))]
    def balanced_nll(logits, temperature=1.):
        loss = torch.nn.functional.cross_entropy(logits / temperature, vy, reduction="none")
        return torch.stack([loss[mask].mean() for mask in masks]).mean()
    def infer(model):
        model.eval()
        with torch.inference_mode():
            return torch.cat([model(vx[i:i + 128].cuda()).cpu() for i in range(0, len(vx), 128)])
    def calibrate(logits):
        temperatures = torch.logspace(-1, 1.3, 100)
        return float(min(temperatures, key=lambda t: float(balanced_nll(logits, t))))
    baseline = torch.load(args.baseline, map_location="cpu", weights_only=True)
    model = FlowResNet().cuda()
    model.load_state_dict(baseline["model_state_dict"])
    baseline_logits = infer(model)
    baseline_metrics = metrics(baseline_logits, vy, data["packets"][validation], baseline["temperature"])
    print("Baseline expanded-validation metrics", baseline_metrics, flush=True)
    # Fresh weights isolate the declared training recipe from prior test choices.
    torch.manual_seed(123)
    model = FlowResNet().cuda()
    optimizer = torch.optim.AdamW(model.parameters(), lr=.0003, weight_decay=.001)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, args.epochs)
    best, state, history = float("inf"), None, []
    for epoch in range(args.epochs):
        model.train()
        for x, y in loader:
            x, y = x.cuda(), y.cuda()
            # Randomly shorten some bursts; never add packet bytes or labels.
            shaped = x.reshape(-1, 16, 32)
            lengths = torch.where(torch.rand(len(x), device="cuda") < (.3 if args.recipe == "balanced" else 0.),
                                  torch.randint(1, 17, (len(x),), device="cuda"), 16)
            shaped = shaped.masked_fill(torch.arange(16, device="cuda")[None, :, None] >= lengths[:, None, None], -1.)
            optimizer.zero_grad(set_to_none=True)
            output_logits = model(shaped.reshape(-1, 1, 512))
            loss = focal(output_logits, y) if args.recipe == "focal" else torch.nn.functional.cross_entropy(output_logits, y, label_smoothing=.05)
            loss.backward()
            optimizer.step()
        scheduler.step()
        logits = infer(model)
        value = float(balanced_nll(logits))
        history.append(dict(epoch=epoch + 1, source_class_balanced_validation_nll=value))
        print(history[-1], flush=True)
        if value < best:
            best, state = value, copy.deepcopy(model.state_dict())
    model.load_state_dict(state)
    logits = infer(model)
    temperature = calibrate(logits)
    result = metrics(logits, vy, data["packets"][validation], temperature)
    # No reductions in UNKNOWN alone can masquerade as safety improvements.
    eligible = (result["benign_escalation_rate"] < baseline_metrics["benign_escalation_rate"]
                and result["benign_attack_alert_rate"] <= baseline_metrics["benign_attack_alert_rate"]
                and result["attack_escalation_recall"] >= baseline_metrics["attack_escalation_recall"] - .005
                and result["macro_f1"] > baseline_metrics["macro_f1"])
    report = dict(experiment="enriched_normal_focal" if args.recipe == "focal" else "source_class_balanced_smoothed_CE_partial_context", seed=123,
                  hyperparameters=dict(recipe=args.recipe, batch_size=64, learning_rate=.0003, weight_decay=.001,
                                       maximum_epochs=args.epochs, optimizer="AdamW", scheduler="cosine"),
                  selection="source/class mean validation NLL", baseline_validation=baseline_metrics,
                  challenger_validation=result, temperature=temperature, eligible_for_test=eligible,
                  test_partition_evaluated=False, history=history,
                  training_samples=int(train.sum()), validation_samples=int(validation.sum()),
                  dataset_sha256=hashlib.sha256(Path(args.data).read_bytes()).hexdigest(),
                  limitation="Validation includes previously inspected HOIC; independent test needed before promotion")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(architecture="flow_resnet18_1d", representation=REPRESENTATION, classes=baseline["classes"],
                   model_state_dict=model.cpu().state_dict(), temperature=temperature,
                   confidence_threshold=.75, entropy_threshold=.8,
                   report=dict(production_ready=False, calibration_valid=True, calibration_validated=False,
                               gates={"independent_evaluation": False}, improvement_experiment=report))
    torch.save(payload, output)
    output.with_suffix(".json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
