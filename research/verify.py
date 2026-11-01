"""Artifact integrity and same-machine prediction replay, not independent review."""
import argparse
from datetime import datetime,timezone
import json
import os
import joblib
import numpy as np
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG",":4096:8")
import torch
from research.dataset import ROOT,digest
from research.models import PrefixModel
from research.run import write,infer,softmax


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run");parser.add_argument("--replay",action="store_true");args=parser.parse_args()
    folder=ROOT/"artifacts/research/runs"/args.run
    config=json.loads((folder/"frozen-config.json").read_text());lock=json.loads((folder/"locked-models.json").read_text())
    checked={name:digest(ROOT/name)==expected for name,expected in lock["code"].items()}
    for model in lock["models"]:checked[model["path"]]=digest(folder/model["path"])==model["sha256"]
    path=ROOT/"artifacts/research"/config["dataset_file"];checked["dataset"]=digest(path)==lock["dataset_sha256"]
    if not all(checked.values()):raise ValueError("Artifact or source integrity check failed")
    data=np.load(path,allow_pickle=False);splits=data["split"]
    for a in set(splits):
        for b in set(splits):
            if a!=b:
                if set(data["group"][splits==a])&set(data["group"][splits==b]):raise ValueError("Capture-group leakage")
                if set(data["session"][splits==a])&set(data["session"][splits==b]):raise ValueError("Exact-session leakage")
    checks=[];torch.set_num_threads(2)
    torch.backends.cudnn.benchmark=False;torch.backends.cudnn.deterministic=True
    torch.use_deterministic_algorithms(True,warn_only=True)
    if args.replay:
        for entry in lock["models"]:
            if entry["metadata"]["kind"]!="torch":continue
            saved=torch.load(folder/entry["path"],map_location="cpu",weights_only=True);spec=saved["spec"]
            model=PrefixModel(spec["kind"],spec["hybrid"]).to("cuda" if torch.cuda.is_available() else "cpu");model.load_state_dict(saved["state_dict"])
            reference=np.load(folder/"predictions"/f"{entry['name']}-{entry['seed']}.npz",allow_pickle=False)
            # Match the original full first batch and FP32 normalization. A
            # different batch can select a different CUDA convolution kernel.
            ids=reference["dev_indices"][:256]
            b=(data["behavior"]-np.array(saved["behavior_mean"],dtype=np.float32))/np.array(saved["behavior_scale"],dtype=np.float32)
            p=softmax(infer(model,data["masked" if spec["masked"] else "unmasked"],b,ids,next(model.parameters()).device),saved["temperatures"])
            expected=reference["development"][:len(ids)];error=float(np.max(np.abs(p-expected)))
            checks.append(dict(model=entry["name"],seed=entry["seed"],samples=len(ids),max_probability_error=error,tolerance=1e-4,passed=error<=1e-4))
    report=dict(verified_at=datetime.now(timezone.utc).isoformat(),artifact_checks=checked,capture_group_and_session_disjoint=True,
        replay_checks=checks,status="passed" if all(c["passed"] for c in checks) else "numeric_mismatch",scope="Same machine, first256 development sessions per neural model; original batch size, determinism and normalization matched",
        independent_human_reproduction=False,warning="This is an integrity/replay check, not a new scientific replication")
    write(folder/"verification.json",report);print(json.dumps(dict(status=report["status"],models=len(checks),independent=False)),flush=True)
    if report["status"]!="passed":raise SystemExit(2)


if __name__=="__main__":main()
