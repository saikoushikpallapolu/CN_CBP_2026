"""Same-CPU-backend FP32/QDQ-INT8 ablation with training-only calibration."""
import argparse
import json
import time
import platform
import numpy as np
import torch
from torch import nn
import onnx
import onnxruntime as ort
from onnxruntime.quantization import CalibrationDataReader,QuantFormat,QuantType,quantize_static,CalibrationMethod
from onnxruntime.quantization.shape_inference import quant_pre_process
from research.dataset import ROOT,digest
from research.models import PrefixModel
from research.adaptive import STAGES
from research.run import write,temperatures,softmax,select_policy,evaluate


class ByteExport(nn.Module):
    def __init__(self,model):super().__init__();self.model=model
    def forward(self,packets):return self.model(packets)


def session(path):
    options=ort.SessionOptions();options.intra_op_num_threads=2;options.inter_op_num_threads=1
    return ort.InferenceSession(str(path),sess_options=options,providers=["CPUExecutionProvider"])


def infer_ort(runtime,arrays,ids):
    batches=[]
    for begin in range(0,len(ids),256):
        rows=ids[begin:begin+256];outputs=[]
        for k in STAGES:
            x=arrays[rows,:k].astype(np.float32)/127.5-1
            outputs.append(runtime.run(None,{"packets":x})[0])
        batches.append(np.stack(outputs,1))
    return np.concatenate(batches)


class Calibration(CalibrationDataReader):
    def __init__(self,arrays,ids):
        self.iterator=iter({"packets":arrays[ids[begin:begin+64],:k].astype(np.float32)/127.5-1} for k in STAGES for begin in range(0,len(ids),64))
    def get_next(self):return next(self.iterator,None)


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run");args=parser.parse_args()
    folder=ROOT/"artifacts/research/runs"/args.run
    if (folder/"FINAL_OPENED.json").exists():raise ValueError("Precision methods must be frozen before opening the final holdout")
    lock=json.loads((folder/"locked-models.json").read_text());config=json.loads((folder/"frozen-config.json").read_text());protocol=config["protocol"]
    if (folder/"precision-lock.json").exists():raise ValueError("Precision experiment already frozen")
    data_path=ROOT/"artifacts/research"/config["dataset_file"]
    if digest(data_path)!=lock["dataset_sha256"]:raise ValueError("Dataset changed")
    data=np.load(data_path,allow_pickle=False);arrays=data["masked"]
    train=np.flatnonzero(data["split"]=="train");val=np.flatnonzero(data["split"]=="validation");dev=np.flatnonzero(data["split"]=="development")
    rng=np.random.default_rng(42);calibration=np.concatenate([rng.choice(train[data["label"][train]==c],min(64,(data["label"][train]==c).sum()),replace=False) for c in range(3)])
    report=dict(scope="Same CPU ONNX Runtime, two threads; byte model only; no GPU/CPU conflation",results=[],calibration_split="train only",calibration_sessions=len(calibration),
                environment=dict(onnx=onnx.__version__,onnxruntime=ort.__version__,torch=torch.__version__,platform=platform.platform()),
                calibration_session_hash=digest_bytes("".join(data["session"][calibration]).encode()),final_status="not_evaluated")
    artifacts=[];torch.set_num_threads(2)
    for entry in lock["models"]:
        if entry["name"]!="resnet1d_prefix":continue
        checkpoint=folder/entry["path"]
        if digest(checkpoint)!=entry["sha256"]:raise ValueError("Checkpoint changed")
        saved=torch.load(checkpoint,map_location="cpu",weights_only=True);model=PrefixModel("1d");model.load_state_dict(saved["state_dict"]);model.eval()
        raw=folder/"models"/f"prefix-{entry['seed']}-export.onnx";fp=folder/"models"/f"prefix-{entry['seed']}-fp32.onnx";integer=folder/"models"/f"prefix-{entry['seed']}-int8.onnx"
        torch.onnx.export(ByteExport(model),torch.zeros(1,16,32),str(raw),input_names=["packets"],output_names=["logits"],
                          dynamic_axes={"packets":{0:"batch",1:"packet_context"},"logits":{0:"batch"}},opset_version=17,dynamo=False)
        onnx.checker.check_model(onnx.load(raw));quant_pre_process(str(raw),str(fp))
        quantize_static(str(fp),str(integer),Calibration(arrays,calibration),quant_format=QuantFormat.QDQ,
                        activation_type=QuantType.QUInt8,weight_type=QuantType.QInt8,per_channel=True,reduce_range=True,calibrate_method=CalibrationMethod.MinMax)
        float_logits=None
        for label,path in (("ort_fp32",fp),("ort_int8",integer)):
            runtime=session(path);lv=infer_ort(runtime,arrays,val);ld=infer_ort(runtime,arrays,dev)
            temp=temperatures(lv,data["label"][val]);pv=softmax(lv,temp);pd=softmax(ld,temp)
            policy=select_policy(pv,data["label"][val],data["length"][val],protocol)
            metrics,curve=evaluate(pd,data["label"][dev],data["length"][dev],data["ready"][dev],data["family"][dev],data["group"][dev],policy)
            x=arrays[train[:64],:16].astype(np.float32)/127.5-1
            for _ in range(10):runtime.run(None,{"packets":x})
            times=[]
            for _ in range(50):
                began=time.perf_counter();runtime.run(None,{"packets":x});times.append((time.perf_counter()-began)*1000)
            name=f"resnet1d_prefix_{label}";item=dict(model=name,seed=entry["seed"],status="measured",split="development",model_sha256=digest(path),parent_checkpoint_sha256=entry["sha256"],
                policy=policy,metrics=metrics,risk_coverage=curve,timings=dict(batch64_context16_cpu_ms_p50=float(np.median(times)),batch64_context16_cpu_ms_p95=float(np.percentile(times,95))),
                calibration_split="train",temperature_selection="validation",temperatures=temp)
            if label=="ort_fp32":float_logits=ld
            else:item["raw_class_agreement_with_ort_fp32"]=float(np.mean(float_logits.argmax(-1)==ld.argmax(-1)));item["max_logit_difference"]=float(np.max(np.abs(float_logits-ld)))
            report["results"].append(item);write(folder/"precision.json",report)
            artifacts.append(dict(name=name,seed=entry["seed"],path=str(path.relative_to(folder)),sha256=digest(path),temperatures=temp,policy=policy,metadata=dict(kind="onnx")))
            print(name,entry["seed"],item["timings"],flush=True)
    write(folder/"precision-lock.json",dict(parent_lock_sha256=digest(folder/"locked-models.json"),models=artifacts,calibration_session_hash=report["calibration_session_hash"]))


def digest_bytes(value):
    import hashlib
    return hashlib.sha256(value).hexdigest()


if __name__=="__main__":main()
