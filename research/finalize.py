"""One-time final evaluation after model/policy locks. No tuning is permitted."""
import argparse
import json
import time
import joblib
import numpy as np
import torch
from sklearn.metrics import roc_auc_score,average_precision_score
from research.dataset import ROOT,digest
from research.models import PrefixModel
from research.run import write,infer,softmax,evaluate
from research.precision import session,infer_ort


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run");parser.add_argument("--regression-final",action="store_true");args=parser.parse_args()
    folder=ROOT/"artifacts/research/runs"/args.run
    if (folder/"final-evaluation.json").exists() or (folder/"FINAL_OPENED.json").exists():raise ValueError("Final holdout was already opened; do not silently reuse it after tuning")
    lock=json.loads((folder/"locked-models.json").read_text());config=json.loads((folder/"frozen-config.json").read_text())
    for name,expected in lock["code"].items():
        if digest(ROOT/name)!=expected:raise ValueError("Frozen method code changed: "+name)
    path=ROOT/"artifacts/research"/config["dataset_file"]
    if digest(path)!=lock["dataset_sha256"]:raise ValueError("Dataset changed")
    entries=list(lock["models"])
    if (folder/"precision-lock.json").exists():
        precision=json.loads((folder/"precision-lock.json").read_text())
        if precision["parent_lock_sha256"]!=digest(folder/"locked-models.json"):raise ValueError("Precision parent mismatch")
        entries+=precision["models"]
    for entry in entries:
        if digest(folder/entry["path"])!=entry["sha256"]:raise ValueError("Model changed")
    ledger_path=ROOT/"artifacts/research/holdout-exposure.json"
    ledger=json.loads(ledger_path.read_text()) if ledger_path.exists() else {"exposures":[]}
    hashes={source["sha256"] for source in config["dataset"]["sources"] if source["split"]=="final"}
    exposed=any(hashes & set(row["source_hashes"]) for row in ledger["exposures"])
    if exposed and not args.regression_final:raise ValueError("A reserved source was already exposed in another run; a new blind cohort is required or explicitly mark regression-only")
    ledger["exposures"].append(dict(run=args.run,time=time.time(),source_hashes=sorted(hashes),scope="regression_only" if exposed else "first_final_opening"))
    write(ledger_path,ledger)
    write(folder/"FINAL_OPENED.json",dict(time=time.time(),locked_models_sha256=digest(folder/"locked-models.json"),evaluation_code_sha256=digest(__file__),warning="Results are now exposed; any further tuning requires a new final cohort"))
    data=np.load(path,allow_pickle=False);ids=np.flatnonzero(data["split"]=="final");results=[]
    torch.set_num_threads(2)
    for entry in entries:
        kind=entry["metadata"]["kind"];model_path=folder/entry["path"]
        if kind=="kitnet":
            saved=joblib.load(model_path);scores=np.array([saved["model"].execute(row.copy()) for row in data["behavior"][ids,2]])
            normal=data["label"][ids]==0;threshold=saved["threshold"]
            item=dict(model=entry["name"],seed=entry["seed"],split="final",model_sha256=entry["sha256"],novelty=dict(
                task="binary novelty, author KitNET on 18 shared features",n=len(ids),threshold=threshold,
                benign_false_alert_rate=float(np.mean(scores[normal]>threshold)),attack_detection_rate=float(np.mean(scores[~normal]>threshold)),
                auroc=float(roc_auc_score(~normal,scores)),aupr=float(average_precision_score(~normal,scores))))
        else:
            if kind=="torch":
                saved=torch.load(model_path,map_location="cpu",weights_only=True);spec=saved["spec"];device="cuda" if torch.cuda.is_available() else "cpu"
                model=PrefixModel(spec["kind"],spec["hybrid"]).to(device);model.load_state_dict(saved["state_dict"])
                behavior=(data["behavior"]-np.array(saved["behavior_mean"]))/np.array(saved["behavior_scale"])
                logits=infer(model,data["masked" if spec["masked"] else "unmasked"],behavior,ids,device);p=softmax(logits,saved["temperatures"])
                adaptive=not bool(spec["fixed"])
            elif kind=="onnx":p=softmax(infer_ort(session(model_path),data["masked"],ids),entry["temperatures"]);adaptive=True
            else:
                model=joblib.load(model_path);p=model.predict_proba(data["behavior"][ids].reshape(-1,18)).reshape(-1,4,3);adaptive=True
            metrics,curve=evaluate(p,data["label"][ids],data["length"][ids],data["ready"][ids],data["family"][ids],data["group"][ids],entry["policy"],adaptive)
            item=dict(model=entry["name"],seed=entry["seed"],split="final",model_sha256=entry["sha256"],policy=entry["policy"],metrics=metrics,risk_coverage=curve)
            np.savez_compressed(folder/"predictions"/f"final-{entry['name']}-{entry['seed']}.npz",probabilities=p,indices=ids)
        results.append(item);print("Final evaluated",entry["name"],entry["seed"],flush=True)
    write(folder/"final-evaluation.json",dict(results=results,n=len(ids),source_groups=sorted(set(data["group"][ids])),class_counts=np.bincount(data["label"][ids],minlength=3).tolist(),
        policy_selection="No fitting, calibration or policy updates on final data",exposure_scope="regression_only" if exposed else "first_final_opening",independent_reproduction="pending_external_person",
        limitations=["Few capture clusters and small novel-family counts","Publisher/schedule labels need independent audit","No guarantee of contemporary enterprise generalization"]))


if __name__=="__main__":main()
