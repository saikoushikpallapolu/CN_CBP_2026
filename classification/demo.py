"""Compare real predictions to separately stored demonstration ground truth."""
import hashlib
import json
from pathlib import Path
from data_processing.production import REPRESENTATION


def load_cases(root):
    folder = Path(root) / "data/production/samples"
    manifest = json.loads((folder / "demo-manifest.json").read_text())
    if manifest["representation"] != REPRESENTATION:
        raise ValueError("Demo representation mismatch")
    for case in manifest["cases"]:
        if case["id"] not in {"demo-normal", "demo-botnet", "demo-ddos", "demo-unseen"}:
            raise ValueError("Unrecognized demo case")
        path = folder / (case["id"] + ".pcap")
        if hashlib.sha256(path.read_bytes()).hexdigest() != case["sha256"]:
            raise ValueError("Demo capture integrity mismatch")
    return manifest


def compare_case(case, result):
    flows = result["flows"]
    expected = case["expected_class"]
    total = len(flows)
    exact = sum(flow["prediction"] == expected for flow in flows)
    unknown = sum(flow["prediction"] == "unknown" for flow in flows)
    attack = sum(flow["prediction"] in ("botnet", "ddos") for flow in flows)
    return dict(id=case["id"], title=case["title"], expected_class=expected,
                source_group=case["source_group"], label_basis=case["label_basis"],
                flow_count=total, counts=result["counts"], class_match_rate=exact / total,
                unknown_rate=unknown / total,
                benign_attack_alert_rate=attack / total if expected == "benign" else None,
                benign_review_rate=(attack + unknown) / total if expected == "benign" else None,
                attack_escalation_rate=(attack + unknown) / total if expected != "benign" else None,
                analysis_ms=result["telemetry"]["analysis_ms"], capture_sha256=case["sha256"])
