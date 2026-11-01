"""Frozen-config multi-seed experiments. Final holdouts are not evaluated here."""
import argparse
import copy
import csv
import hashlib
import importlib.metadata
import json
import platform
import random
import time
import os
from datetime import datetime,timezone
from pathlib import Path
import uuid
import joblib
import numpy as np
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG",":4096:8")
import torch
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from ml.production_model import FocalLoss
from research.models import PrefixModel
from research.adaptive import STAGES,decide
from research.metrics import summarize,clustered_intervals
from research.dataset import ROOT,digest

SPECS=[dict(name="resnet1d_prefix",kind="1d",hybrid=False,masked=True,fixed=None),
       dict(name="resnet1d_fixed16",kind="1d",hybrid=False,masked=True,fixed=16),
       dict(name="resnet2d_prefix",kind="2d",hybrid=False,masked=True,fixed=None),
       dict(name="resnet1d_unmasked",kind="1d",hybrid=False,masked=False,fixed=None),
       dict(name="hybrid_prefix",kind="1d",hybrid=True,masked=True,fixed=None)]


def package_versions():
    versions={}
    for name in ("torch","numpy","scikit-learn","scipy","onnxruntime","onnx"):
        try:versions[name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:versions[name]=None
    return versions


def write(path,value):
    path=Path(path);tmp=path.with_suffix(path.suffix+".part")
    tmp.write_text(json.dumps(value,indent=2,allow_nan=False));tmp.replace(path)


def softmax(logits,temperatures):
    x=logits/np.asarray(temperatures)[None,:,None];x=x-x.max(-1,keepdims=True)
    p=np.exp(x);return p/p.sum(-1,keepdims=True)


def temperatures(logits,y):
    selected=[]
    for index in range(4):
        losses=[]
        for temperature in np.logspace(-1,1.3,60):
            p=softmax(logits[:,index:index+1,:],[temperature])[:,0]
            ce=-np.log(np.maximum(p[np.arange(len(y)),y],1e-12))
            losses.append(np.mean([ce[y==label].mean() for label in np.unique(y)]))
        selected.append(float(np.logspace(-1,1.3,60)[np.argmin(losses)]))
    return selected


def select_policy(p,y,lengths,protocol,fixed=None):
    candidates=[]
    for threshold in protocol["thresholds"]:
        decision=decide(p,lengths,threshold,protocol["entropy_limit"],fixed=fixed);m=summarize(y,decision)
        fp=m["benign_false_alert_rate"];review=m["benign_review_rate"];miss=m["attack_accepted_benign_rate"]
        feasible=fp is not None and review is not None and fp<=protocol["selection_benign_false_alert_budget"] and review<=protocol["selection_benign_review_budget"] and (miss or 0)<=.1
        violation=max(0,(fp or 0)-protocol["selection_benign_false_alert_budget"])+max(0,(review or 0)-protocol["selection_benign_review_budget"])+max(0,(miss or 0)-.1)
        candidates.append((not feasible,violation,m["mean_packets"],-m["correct_accepted_fraction"],threshold,m))
    chosen=min(candidates,key=lambda row:row[:4])
    return dict(threshold=chosen[4],feasible=not chosen[0],validation_metrics=chosen[5],
                selection="Validation only; minimize constraint violation then packets; infeasible is never a deployment pass")


def infer(model,arrays,behavior,indices,device,batch=256):
    model.eval();out=[]
    with torch.inference_mode():
        for begin in range(0,len(indices),batch):
            selected=indices[begin:begin+batch];stages=[]
            for i,k in enumerate(STAGES):
                x=torch.from_numpy(arrays[selected,:k].astype(np.float32)/127.5-1).to(device)
                b=torch.from_numpy(behavior[selected,i].astype(np.float32)).to(device)
                stages.append(model(x,b).cpu().numpy())
            out.append(np.stack(stages,axis=1))
    return np.concatenate(out)


def evaluate(p,y,lengths,ready,family,groups,policy,adaptive=True):
    results={}
    for name,fixed,threshold in [("adaptive",None,policy["threshold"]),("fixed4",4,policy["threshold"]),("fixed8",8,policy["threshold"]),
                                 ("fixed16",16,policy["threshold"]),("fixed32",32,policy["threshold"]),("no_rejection_fixed16",16,0.)]:
        if not adaptive and name not in ("fixed16","no_rejection_fixed16"):continue
        d=decide(p,lengths,threshold,1. if threshold==0 else .8,fixed=fixed)
        m=summarize(y,d,family);m["context_wait_ms_p50"]=float(np.median(ready[np.arange(len(y)),d["stage_index"]])*1000)
        m["context_wait_ms_p95"]=float(np.percentile(ready[np.arange(len(y)),d["stage_index"]],95)*1000)
        # Each adaptive decision pays for every preceding prefix inference.
        m["mean_model_calls"]=float(np.mean(d["stage_index"]+1)) if fixed is None else 1.
        m["confidence_intervals"]=clustered_intervals(y,d,groups,repeats=200)
        results[name]=m
    curve=[]
    for threshold in np.linspace(.34,.999,31):
        m=summarize(y,decide(p,lengths,float(threshold),.8,fixed=None if adaptive else 16))
        curve.append(dict(threshold=float(threshold),coverage=m["coverage"],risk=m["selective_error"],benign_false_alert_rate=m["benign_false_alert_rate"],benign_review_rate=m["benign_review_rate"]))
    return results,curve


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--data",default="artifacts/research/frozen-v1.npz")
    parser.add_argument("--run-id");parser.add_argument("--device",choices=("cuda","cpu"),default="cuda");args=parser.parse_args()
    protocol=json.loads((ROOT/"research/protocol.json").read_text());path=ROOT/args.data
    manifest=json.loads(path.with_suffix(".json").read_text())
    if digest(path)!=manifest["dataset_sha256"] or digest(ROOT/"research/protocol.json")!=manifest["protocol_sha256"]:raise ValueError("Frozen dataset or protocol changed")
    run_id=args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:8]
    if not run_id.replace("-","").replace("_","").isalnum():raise ValueError("Invalid run id")
    folder=ROOT/"artifacts/research/runs"/run_id;folder.mkdir(parents=True,exist_ok=False)
    (folder/"models").mkdir();(folder/"predictions").mkdir()
    torch.set_num_threads(2);device=torch.device(args.device)
    torch.backends.cudnn.benchmark=False;torch.backends.cudnn.deterministic=True
    torch.use_deterministic_algorithms(True,warn_only=True)
    if args.device=="cuda" and not torch.cuda.is_available():raise RuntimeError("Requested GPU is unavailable")
    code={str(p.relative_to(ROOT)):digest(p) for p in [ROOT/"research"/name for name in ("run.py","models.py","adaptive.py","metrics.py","dataset.py")] +
          [ROOT/name for name in ("data_processing/production.py","classification/behavior.py","ml/production_model.py")] + list((ROOT/"research/vendor/kitnet").glob("*.py")) + [ROOT/"research/vendor/kitnet/UPSTREAM.json"]}
    frozen=dict(run_id=run_id,created_at=datetime.now(timezone.utc).isoformat(),protocol=protocol,protocol_sha256=digest(ROOT/"research/protocol.json"),dataset=manifest,
                code=code,environment=dict(python=platform.python_version(),platform=platform.platform(),device=str(device),gpu=torch.cuda.get_device_name(0) if device.type=="cuda" else None,
                    versions=package_versions()),
                dataset_file=path.name,final_status="sealed_not_evaluated",independent_reproduction="pending_external_person",models=SPECS)
    write(folder/"frozen-config.json",frozen)
    data=np.load(path,allow_pickle=False);train=np.flatnonzero(data["split"]=="train");val=np.flatnonzero(data["split"]=="validation");dev=np.flatnonzero(data["split"]=="development")
    mean=data["behavior"][train].mean((0,1));scale=np.maximum(data["behavior"][train].std((0,1)),1e-4)
    behavior=(data["behavior"]-mean)/scale
    results=[];artifacts=[]
    def update(status,**extra):
        write(folder/"summary.json",dict(run_id=run_id,status=status,results=results,**extra))
    def record(name,seed,pv,pd,model_path,metadata,adaptive):
        policy=select_policy(pv,data["label"][val],data["length"][val],protocol,fixed=None if adaptive else 16)
        metrics,curve=evaluate(pd,data["label"][dev],data["length"][dev],data["ready"][dev],data["family"][dev],data["group"][dev],policy,adaptive)
        item=dict(model=name,seed=seed,split="development",model_sha256=digest(model_path),policy=policy,metrics=metrics,risk_coverage=curve,**metadata)
        write(folder/f"{name}-{seed}.json",item)
        np.savez_compressed(folder/"predictions"/f"{name}-{seed}.npz",validation=pv,development=pd,val_indices=val,dev_indices=dev)
        results.append(item);artifacts.append(dict(name=name,seed=seed,path=str(model_path.relative_to(folder)),sha256=digest(model_path),policy=policy,metadata=metadata))
        update("running",current=name,seed=seed)
    for seed in protocol["seeds"]:
        for spec in SPECS:
            name=spec["name"];random.seed(seed);np.random.seed(seed);torch.manual_seed(seed);torch.cuda.manual_seed_all(seed)
            model=PrefixModel(spec["kind"],spec["hybrid"]).to(device)
            arrays=data["masked" if spec["masked"] else "unmasked"]
            optimizer=torch.optim.AdamW(model.parameters(),lr=.001,weight_decay=1e-4)
            counts=np.bincount(data["label"][train],minlength=3)
            criterion=FocalLoss(weight=torch.tensor(len(train)/(3*np.maximum(counts,1)),dtype=torch.float32,device=device))
            rng=np.random.default_rng(seed);best=float("inf");state=None;history=[];started=time.perf_counter()
            for epoch in range(protocol["epochs"]):
                model.train();loss_sum=0.;order=rng.permutation(train)
                for begin in range(0,len(order),protocol["batch_size"]):
                    ids=order[begin:begin+protocol["batch_size"]];k=spec["fixed"] or int(rng.choice(STAGES));index=STAGES.index(k)
                    x=torch.from_numpy(arrays[ids,:k].astype(np.float32)/127.5-1).to(device)
                    b=torch.from_numpy(behavior[ids,index].astype(np.float32)).to(device);y=torch.from_numpy(data["label"][ids]).long().to(device)
                    optimizer.zero_grad(set_to_none=True);loss=criterion(model(x,b),y);loss.backward();optimizer.step();loss_sum+=float(loss.detach())
                logits=infer(model,arrays,behavior,val,device);indices=[STAGES.index(spec["fixed"])] if spec["fixed"] else range(4)
                loss_val=np.mean([np.mean([(-np.log(np.maximum(softmax(logits[:,i:i+1], [1.])[:,0][np.arange(len(val)),data["label"][val]],1e-12)))[data["label"][val]==label].mean() for label in (0,1,2)]) for i in indices])
                history.append(dict(epoch=epoch+1,training_loss=loss_sum,validation_macro_ce=float(loss_val)))
                if loss_val<best:best=float(loss_val);state=copy.deepcopy(model.state_dict())
                update("running",current=name,seed=seed,epoch=epoch+1,history=history);print(run_id,name,seed,epoch+1,round(float(loss_val),4),flush=True)
            model.load_state_dict(state);lv=infer(model,arrays,behavior,val,device);ld=infer(model,arrays,behavior,dev,device);temp=temperatures(lv,data["label"][val])
            model_path=folder/"models"/f"{name}-{seed}.pth"
            torch.save(dict(state_dict={k:v.cpu() for k,v in state.items()},spec=spec,temperatures=temp,behavior_mean=mean.tolist(),behavior_scale=scale.tolist(),stages=list(STAGES)),model_path)
            record(name,seed,softmax(lv,temp),softmax(ld,temp),model_path,dict(kind="torch",spec=spec,parameters=sum(p.numel() for p in model.parameters()),training_seconds=time.perf_counter()-started,history=history,temperatures=temp),not bool(spec["fixed"]))
            del model;torch.cuda.empty_cache()
        for name in ("logistic_behavior","forest_behavior"):
            started=time.perf_counter();x=data["behavior"][train].reshape(-1,18);y=np.repeat(data["label"][train],4)
            model=make_pipeline(StandardScaler(),LogisticRegression(max_iter=500,class_weight="balanced",random_state=seed)) if name.startswith("logistic") else RandomForestClassifier(n_estimators=96,max_depth=12,min_samples_leaf=4,class_weight="balanced_subsample",n_jobs=2,random_state=seed)
            model.fit(x,y);pv=model.predict_proba(data["behavior"][val].reshape(-1,18)).reshape(-1,4,3);pd=model.predict_proba(data["behavior"][dev].reshape(-1,18)).reshape(-1,4,3)
            model_path=folder/"models"/f"{name}-{seed}.joblib";joblib.dump(model,model_path)
            record(name,seed,pv,pd,model_path,dict(kind="sklearn",training_seconds=time.perf_counter()-started,features="18 causal behavior features; distinct input modality"),True)
        # Author KitNET algorithm on identical 18 behavioral features. This is
        # not a reproduction of the paper's original Kitsune feature extractor.
        previous=np.geterr()
        from research.vendor.kitnet.KitNET import KitNET
        np.seterr(**previous);np.random.seed(seed)
        normal=train[data["label"][train]==0];normal=normal[np.argsort(data["first_timestamp"][normal],kind="stable")]
        grace=min(500,max(10,len(normal)//3));kit=KitNET(18,5,grace,max(1,len(normal)-grace-1))
        for feature in data["behavior"][normal,2]:kit.train(feature.copy())
        validation_scores=np.array([[kit.execute(row.copy()) for row in sample] for sample in data["behavior"][val]])
        normal_score=validation_scores[data["label"][val]==0]
        threshold=float(np.quantile(normal_score,.99));dev_scores=np.array([[kit.execute(row.copy()) for row in sample] for sample in data["behavior"][dev]])
        kit_path=folder/"models"/f"kitnet18-{seed}.joblib";joblib.dump(dict(model=kit,threshold=threshold),kit_path)
        from sklearn.metrics import roc_auc_score,average_precision_score
        m=dict(n=len(dev),task="binary novelty",features="KitNET author algorithm, 18 shared causal features; not original full Kitsune pipeline",threshold=threshold,
               benign_false_alert_rate=float(np.mean(dev_scores[data["label"][dev]==0,2]>threshold)),
               attack_detection_rate=float(np.mean(dev_scores[data["label"][dev]!=0,2]>threshold)),
               auroc=float(roc_auc_score(data["label"][dev]!=0,dev_scores[:,2])),aupr=float(average_precision_score(data["label"][dev]!=0,dev_scores[:,2])))
        item=dict(model="kitnet18",seed=seed,split="development",model_sha256=digest(kit_path),novelty=m)
        item["seed_semantics"]="Author autoencoders initialize with fixed RandomState(1234); repeated deterministic baseline, not independent stochastic seeds"
        np.savez_compressed(folder/"predictions"/f"kitnet18-{seed}.npz",validation_scores=validation_scores,development_scores=dev_scores,val_indices=val,dev_indices=dev)
        results.append(item);write(folder/f"kitnet18-{seed}.json",item);artifacts.append(dict(name="kitnet18",seed=seed,path=str(kit_path.relative_to(folder)),sha256=digest(kit_path),metadata=dict(kind="kitnet")))
        update("running",current="kitnet18",seed=seed)
    write(folder/"locked-models.json",dict(run_id=run_id,protocol_sha256=frozen["protocol_sha256"],dataset_sha256=manifest["dataset_sha256"],code=code,models=artifacts,
                                        locked_at=datetime.now(timezone.utc).isoformat(),final_status="not_evaluated"))
    update("development_complete",final_status="sealed_not_evaluated",independent_reproduction="pending_external_person")
    print("DEVELOPMENT COMPLETE",folder,flush=True)


if __name__=="__main__":main()
