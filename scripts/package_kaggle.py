"""Package tensor data and training source, without raw PCAPs or credentials."""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path
import numpy as np


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/production/dataset.npz")
    parser.add_argument("--output", default="artifacts/kaggle/trafficscan-training.zip")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    dataset = root / args.data
    with np.load(dataset, allow_pickle=False) as data:
        if set(data["split"]) != {"train", "validation", "test"}:
            raise ValueError("All independent partitions are required")
        for first, second in (("train", "validation"), ("train", "test"), ("validation", "test")):
            if set(data["source"][data["split"] == first]) & set(data["source"][data["split"] == second]):
                raise ValueError("Source leakage")
    files = ["ml/train_production.py", "ml/production_model.py", "ml/export_production.py", "ml/evaluate_export.py",
             "data_processing/production.py", "artifacts/identity_audit.json"]
    destination = root / args.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(), "contains_raw_captures": False}
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(dataset, "data/production/dataset.npz")
        for relative in files:
            path = root / relative
            if not path.is_file():
                raise ValueError("Required evidence/source missing: " + relative)
            bundle.write(path, relative)
        if dataset.with_suffix(".json").exists():
            bundle.write(dataset.with_suffix(".json"), "data/production/dataset.json")
        bundle.writestr("bundle.json", json.dumps(manifest, indent=2))
    print(destination)


if __name__ == "__main__":
    main()
