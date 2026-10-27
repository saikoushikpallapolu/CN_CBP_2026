"""Create a source/weights/sample review bundle without raw corpora or history."""
import argparse
import hashlib
import json
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="artifacts/release/trafficscan-review.zip")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=root, text=True).splitlines()
    folders = {"api", "classification", "data_processing", "deploy", "docs", "frontend", "ml", "native", "scripts", "tests"}
    root_files = {"README.md", "pytest.ini", ".dockerignore", ".gitignore", "download_tuesday.py"}
    selected = {}
    for name in names:
        path = Path(name)
        if path.parts[0] in folders or name in root_files or name.startswith("requirements") and name.endswith(".txt") or name in {"data/DATASET_CITATIONS.md", "data/production_sources.json"}:
            selected[name] = root / name
    suffixes = (".pth", ".json", ".onnx", ".int8.onnx", ".trt.onnx", ".trt.int8.onnx", ".engine", ".engine.json", ".engine.audit.json")
    for model in ("flow_resnet", "candidate_flow_resnet"):
        for suffix in suffixes:
            name = "ml/checkpoints/" + model + suffix
            path = root / name
            if not path.is_file():
                raise ValueError("Missing reviewed model artifact: " + name)
            selected[name] = path
    for name in ("monday", "ctu1", "friday", "cse", "mawi"):
        relative = "data/production/samples/" + name + ".pcap"
        selected[relative] = root / relative
    for name in ("dataset.npz", "dataset.json"):
        relative = "data/production/" + name
        selected[relative] = root / relative
    for path in (root / "data/external").glob("*/source.json"):
        selected[path.relative_to(root).as_posix()] = path
    checkpoint = hashlib.sha256((root / "ml/checkpoints/flow_resnet.pth").read_bytes()).hexdigest()
    engine = json.loads((root / "ml/checkpoints/flow_resnet.engine.json").read_text())
    if engine["checkpoint_sha256"] != checkpoint:
        raise ValueError("Canonical engine/checkpoint identity mismatch")
    training_report = json.loads((root / "ml/checkpoints/flow_resnet.json").read_text())
    if training_report["dataset_sha256"] != hashlib.sha256((root / "data/production/dataset.npz").read_bytes()).hexdigest():
        raise ValueError("Frozen training data does not match its recorded report")
    manifest = dict(created_at=datetime.now(timezone.utc).isoformat(), mode="experimental review",
                    checkpoint_sha256=checkpoint, gpu=engine["gpu"], runtime=engine["target_runtime"],
                    excluded=["raw acquisition corpora", "investigation database", "API credentials", "Python environments", "GPU vendor libraries"],
                    files={})
    output = (root / args.output).resolve()
    if not output.is_relative_to((root / "artifacts").resolve()):
        raise ValueError("Review bundles must stay within artifacts")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output.with_suffix(".zip.part"), "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, path in sorted(selected.items()):
            payload = path.read_bytes()
            manifest["files"][name] = dict(size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
            bundle.writestr(name, payload)
        bundle.writestr("REVIEW_MANIFEST.json", json.dumps(manifest, indent=2))
    output.with_suffix(".zip.part").replace(output)
    output.with_suffix(".sha256").write_text(hashlib.sha256(output.read_bytes()).hexdigest() + "  " + output.name + "\n")
    print(output, output.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
