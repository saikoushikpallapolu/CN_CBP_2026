"""Matched hardware/input timing and a separately scoped PNG codec ablation."""
import argparse
import io
import json
import time
import numpy as np
from PIL import Image
import torch
from research.dataset import ROOT,digest
from research.models import PrefixModel
from research.adaptive import STAGES
from research.run import write


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run");args=parser.parse_args();folder=ROOT/"artifacts/research/runs"/args.run
    config=json.loads((folder/"frozen-config.json").read_text());lock=json.loads((folder/"locked-models.json").read_text())
    data=np.load(ROOT/"artifacts/research"/config["dataset_file"],allow_pickle=False);ids=np.flatnonzero(data["split"]=="train")[:64]
    device="cuda" if torch.cuda.is_available() else "cpu";torch.set_num_threads(2);results=[]
    for entry in lock["models"]:
        if entry["metadata"]["kind"]!="torch":continue
        path=folder/entry["path"]
        if digest(path)!=entry["sha256"]:raise ValueError("Model changed")
        saved=torch.load(path,map_location="cpu",weights_only=True);spec=saved["spec"];model=PrefixModel(spec["kind"],spec["hybrid"]).to(device);model.load_state_dict(saved["state_dict"]);model.eval()
        for index,k in enumerate(STAGES):
            x=torch.from_numpy(data["masked" if spec["masked"] else "unmasked"][ids,:k].astype(np.float32)/127.5-1)
            b=torch.from_numpy(((data["behavior"][ids,index]-np.array(saved["behavior_mean"]))/np.array(saved["behavior_scale"])).astype(np.float32))
            def invoke():
                with torch.inference_mode():return model(x.to(device),b.to(device)).cpu().numpy()
            for _ in range(10):invoke()
            times=[]
            for _ in range(50):
                started=time.perf_counter();invoke();times.append((time.perf_counter()-started)*1000)
            results.append(dict(model=entry["name"],seed=entry["seed"],packets=k,batch=len(ids),device=device,p50_ms=float(np.median(times)),p95_ms=float(np.percentile(times,95)),parameters=entry["metadata"]["parameters"]))
        print("Measured matched kernel",entry["name"],entry["seed"],flush=True)
    arrays=data["masked"][ids,:16]
    def direct():return arrays.astype(np.float32)/127.5-1
    def png():
        decoded=[]
        for array in arrays:
            buffer=io.BytesIO();Image.fromarray(array).save(buffer,format="PNG");buffer.seek(0)
            with Image.open(buffer) as image:decoded.append(np.array(image,dtype=np.uint8))
        return np.stack(decoded).astype(np.float32)/127.5-1
    assert np.array_equal(direct(),png())
    codec={}
    for name,fn in (("direct_tensor_array",direct),("png_round_trip",png)):
        for _ in range(5):fn()
        values=[]
        for _ in range(40):
            began=time.perf_counter();fn();values.append((time.perf_counter()-began)*1000)
        codec[name]=dict(p50_ms=float(np.median(values)),p95_ms=float(np.percentile(values,95)))
    write(folder/"cost.json",dict(kernel_scope="Same PyTorch FP32 backend/device, matched prefix bytes, batch64, includes host/device copies; excludes parsing, context waiting and feature extraction",results=results,
        png_scope="Same CPU, 64 identical 16x32 byte arrays; in-memory codec round trip only, not end-to-end speedup. The 2D model consumes tensors directly and is not forced through PNG.",png=codec,png_bit_exact=True))


if __name__=="__main__":main()
