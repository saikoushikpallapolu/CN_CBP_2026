"""Train independent advisory behavior and novelty models with source-held-out checks."""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, f1_score
from classification.behavior import BehaviorContext, BehaviorDetector, FEATURES, VERSION
from data_processing.production import flow_bursts, read_capture
from data_processing.build_production import FlowLabels, cic_label
from scripts.prepare_cse import schedule_label

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ["benign", "botnet", "ddos"]


def sources():
    from scripts.acquire_production_data import load_manifest
    manifest = load_manifest(ROOT / "data/external/acquisition.json")
    for name, split in [("monday", "train"), ("normal7-behavior", "train"), ("normal-dns", "train"),
                        ("ctu1", "train"), ("ctu2", "train"), ("wednesday", "train"), ("cse", "train"),
                        ("ctu-normal", "validation"), ("ctu9", "validation"), ("cse21", "validation"),
                        ("normal9-behavior", "test"), ("ctu10", "test"), ("friday", "test"), ("cse21-hoic", "challenge")]:
        path = ROOT / "data/external" / name / "capture.pcap"
        if name == "monday" and not path.exists():
            path = ROOT / "data/raw/benign/Monday-WorkingHours_slice100MB.pcap"
        if not path.exists(): continue
        if name in ("monday", "normal7-behavior", "normal9-behavior", "ctu-normal", "normal-dns"):
            labeler = lambda p: "benign"
        elif name.startswith("ctu"):
            labeler = FlowLabels(path.with_name("labels.csv")); labeler.align_capture_clock(path)
        elif name in ("cse", "cse21", "cse21-hoic"):
            audit = manifest[name]["label_audit"]
            labeler = lambda p, audit=audit: schedule_label(p, audit)
        else: labeler = lambda p, name=name: cic_label(name, p)
        yield name, split, path, labeler


def build(max_packets, max_flows):
    features, labels, groups, splits, identities, provenance = [], [], [], [], set(), []
    for name, split, path, labeler in sources():
        context = BehaviorContext(); accepted = 0
        for packets in flow_bursts(read_capture(path, max_packets=max_packets, allow_truncated="slice100MB" in path.name), on_packet=context.observe):
            truth = {labeler(p) for p in packets}
            if len(truth) != 1 or None in truth: continue
            identity = hashlib.sha256(b"".join(p.raw + np.float64(p.timestamp).tobytes() for p in packets)).digest()
            if identity in identities: continue
            identities.add(identity)
            features.append(context.features(packets[0])); labels.append(CLASSES.index(truth.pop())); groups.append(name); splits.append(split)
            accepted += 1
            if accepted >= max_flows: break
        provenance.append(dict(source=name, split=split, flows=accepted, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        print(name, split, accepted, flush=True)
    return np.asarray(features), np.array(labels), np.array(groups), np.array(splits), provenance


def expected_depth(n):
    if n <= 1: return 0.
    if n == 2: return 1.
    return 2 * (np.log(n - 1) + np.euler_gamma) - 2 * (n - 1) / n


def export_tree(tree, isolation=False):
    depth = np.zeros(tree.node_count)
    for node in range(tree.node_count):
        if tree.children_left[node] >= 0:
            depth[tree.children_left[node]] = depth[node] + 1; depth[tree.children_right[node]] = depth[node] + 1
    values = [[float(depth[i] + expected_depth(n))] for i,n in enumerate(tree.n_node_samples)] if isolation else tree.value[:,0,:].tolist()
    if not isolation:
        values = [[v / max(sum(row), 1e-12) for v in row] for row in values]
    else: values = [row[0] for row in values]
    return dict(left=tree.children_left.tolist(), right=tree.children_right.tolist(), feature=tree.feature.tolist(),
                threshold=tree.threshold.tolist(), value=values)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-packets", type=int, default=200000)
    parser.add_argument("--max-flows", type=int, default=6000)
    parser.add_argument("--output", default="ml/checkpoints/behavior_detector.json")
    args = parser.parse_args()
    x,y,source,split,provenance = build(args.max_packets,args.max_flows)
    train, validation = split == "train", split == "validation"
    assert not set(source[train]) & set(source[~train])
    assert set(y[train]) == {0,1,2} and ((y == 0) & validation).any()
    classifier = RandomForestClassifier(n_estimators=96, max_depth=12, min_samples_leaf=4,
                                        class_weight="balanced_subsample", n_jobs=2, random_state=42).fit(x[train],y[train])
    # Fit novelty on known normal only; balance sources without inventing flows.
    normal_indices = []
    for name in sorted(set(source[train & (y == 0)])):
        indexes = np.flatnonzero(train & (y == 0) & (source == name))
        normal_indices.extend(np.random.default_rng(42).choice(indexes, min(len(indexes), 1500), replace=False))
    isolation = IsolationForest(n_estimators=96, max_samples=256, random_state=42, n_jobs=2).fit(x[normal_indices])
    # Threshold selection sees only validation normals, separately per source.
    threshold = max(float(np.quantile(-isolation.score_samples(x[validation & (y == 0) & (source == name)]), .99))
                    for name in set(source[validation & (y == 0)]))
    report = dict(status="advisory_only", training_flows=int(train.sum()), normal_training_flows=len(normal_indices),
                  feature_context="Causal latest 128 packets and rolling 1-second destination activity; no IP/port/absolute-time features",
                  threshold_selection="Maximum per-source validation-normal 99th percentile; test/challenge excluded",
                  data=provenance, per_source={},
                  limitations=["HOIC is an already-inspected challenge, not a new untouched test", "No independent enterprise audit", "Small source-specific subsets", "Retimed simulations change rate/timing features", "Advisory evidence cannot establish maliciousness"])
    for name in sorted(set(source)):
        mask = source == name
        predicted = classifier.predict(x[mask]); anomalous = -isolation.score_samples(x[mask]) >= threshold
        report["per_source"][name] = dict(split=str(split[mask][0]), flows=int(mask.sum()), class_counts=np.bincount(y[mask],minlength=3).tolist(),
            accuracy=float(accuracy_score(y[mask],predicted)), macro_f1=float(f1_score(y[mask],predicted,labels=[0,1,2],average="macro",zero_division=0)),
            benign_false_attack_rate=float(np.mean(predicted[y[mask] == 0] != 0)) if (y[mask] == 0).any() else None,
            attack_recall=float(np.mean(predicted[y[mask] != 0] != 0)) if (y[mask] != 0).any() else None,
            benign_anomaly_rate=float(np.mean(anomalous[y[mask] == 0])) if (y[mask] == 0).any() else None,
            attack_anomaly_rate=float(np.mean(anomalous[y[mask] != 0])) if (y[mask] != 0).any() else None)
    independent = [v for v in report["per_source"].values() if v["split"] != "train"]
    report["promotion_gates"] = dict(benign_false_alerts=all(v["benign_false_attack_rate"] is None or v["benign_false_attack_rate"] <= .01 for v in independent),
        attack_recall=all(v["attack_recall"] is None or v["attack_recall"] >= .90 for v in independent),
        benign_anomalies=all(v["benign_anomaly_rate"] is None or v["benign_anomaly_rate"] <= .01 for v in independent), independent_enterprise_audit=False)
    artifact = dict(representation=VERSION, features=FEATURES, classifier=[export_tree(t.tree_) for t in classifier.estimators_],
                    isolation=[export_tree(t.tree_,True) for t in isolation.estimators_], isolation_normalizer=expected_depth(isolation.max_samples_),
                    anomaly_threshold=threshold, report=report)
    destination=ROOT / args.output; destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(artifact,separators=(",",":")))
    # The safe JSON runtime must reproduce sklearn before deployment.
    runtime = BehaviorDetector(destination); probe=x[::max(1,len(x)//256)]
    check=runtime.predict(probe)
    assert np.allclose([r["anomaly_score"] for r in check],-isolation.score_samples(probe),atol=1e-7)
    assert np.allclose([list(r["probabilities"].values()) for r in check],classifier.predict_proba(probe),atol=1e-7)
    report["json_runtime_parity"] = True
    destination.write_text(json.dumps(artifact,separators=(",",":")))
    Path("artifacts/behavior-evaluation.json").write_text(json.dumps(report,indent=2))
    np.savez_compressed("artifacts/behavior-features.npz",x=x,y=y,source=source,split=split)
    print(json.dumps(report,indent=2),flush=True)


if __name__ == "__main__": main()
