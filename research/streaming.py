"""Isolated queue-based incremental inference with original PCAP pacing.

No sockets, demo continuations or precomputed predictions are used. Artificial
clip boundaries censor incomplete sessions rather than forcing early verdicts.
"""
import argparse
from collections import OrderedDict
import json
from pathlib import Path
import queue
import threading
import time
import numpy as np
import psutil
import torch
from classification.behavior import BehaviorContext
from data_processing.production import read_capture,parse_packet,packet_features
from research.adaptive import IncrementalDecision,STAGES
from research.models import PrefixModel
from research.dataset import ROOT,digest
from research.run import write


def replay(checkpoint,path,seconds=5.,speed=1.,capacity=256,fixed=None,device="cuda"):
    saved=torch.load(checkpoint,map_location="cpu",weights_only=True);spec=saved["spec"]
    model=PrefixModel(spec["kind"],spec["hybrid"]).to(device);model.load_state_dict(saved["state_dict"]);model.eval()
    mean=np.array(saved["behavior_mean"]);scale=np.array(saved["behavior_scale"])
    if device=="cuda":
        with torch.inference_mode():model(torch.zeros(1,16,32,device=device),torch.zeros(1,18,device=device))
        torch.cuda.synchronize();torch.cuda.reset_peak_memory_stats()
    behavior=BehaviorContext();q=queue.Queue(maxsize=capacity);stop=threading.Event()
    stats=dict(offered=0,processed=0,dropped_by_queue=0,queue_peak=0,inference_calls=0,decisions=[],inference_ms=[],rss_peak=0)
    producer_error=[];sentinel=object();active=OrderedDict();completed=OrderedDict()
    def produce():
        try:
            first=None;start=time.perf_counter();previous=0.
            for stamp,raw,link in read_capture(path,max_packets=50000):
                if first is None:first=stamp
                elapsed=max(previous,stamp-first);previous=elapsed
                if elapsed>seconds:break
                due=start+elapsed/speed
                while not stop.is_set() and time.perf_counter()<due:stop.wait(min(.02,due-time.perf_counter()))
                if stop.is_set():break
                offered=time.perf_counter();stats["offered"]+=1
                try:q.put_nowait((stamp,raw,link,offered));stats["queue_peak"]=max(stats["queue_peak"],q.qsize())
                except queue.Full:stats["dropped_by_queue"]+=1
        except Exception as error:producer_error.append(str(error))
        finally:
            while not stop.is_set():
                try:q.put(sentinel,timeout=.1);break
                except queue.Full:pass
    started=time.perf_counter();worker=threading.Thread(target=produce,daemon=True);worker.start()
    try:
        while True:
            item=q.get(timeout=max(20,seconds/speed+10))
            if item is sentinel:break
            stamp,raw,link,offered=item;stats["processed"]+=1
            packet=parse_packet(raw,stamp,link);behavior.observe(packet,stamp,raw,link)
            if packet is None:continue
            syn=packet.protocol==6 and raw[packet.transport_offset+13]&0x12==2
            isn=raw[packet.transport_offset+4:packet.transport_offset+8] if syn else None
            key=packet.key;done=completed.pop(key,None)
            if done and stamp-done[0]<=30 and (not syn or done[1]==isn):completed[key]=(stamp,done[1]);continue
            state=active.pop(key,None)
            if state and (stamp-state["last"]>30 or (syn and state["isn"] is not None and isn!=state["isn"])):
                stats.setdefault("censored_at_session_boundary",0);stats["censored_at_session_boundary"]+=1;state=None
            if state is None:
                state=dict(packets=[],first_arrival=offered,isn=isn,last=stamp)
                def infer(context):
                    count=len(context);target=fixed or next((s for s in STAGES if s>=count),32)
                    x=np.zeros((target,32),dtype=np.uint8)
                    for i,p in enumerate(context[:target]):x[i]=np.frombuffer(packet_features(p,mask=spec["masked"]),dtype=np.uint8)
                    features=(behavior.features(context[0])-mean)/scale
                    xb=torch.from_numpy(x.astype(np.float32)/127.5-1)[None].to(device)
                    fb=torch.from_numpy(features.astype(np.float32))[None].to(device)
                    if device=="cuda":torch.cuda.synchronize()
                    began=time.perf_counter()
                    with torch.inference_mode():logits=model(xb,fb)[0]/saved["temperatures"][STAGES.index(target)];p=torch.softmax(logits,0).cpu().numpy()
                    if device=="cuda":torch.cuda.synchronize()
                    stats["inference_ms"].append((time.perf_counter()-began)*1000);stats["inference_calls"]+=1
                    return p
                state["detector"]=IncrementalDecision(infer,threshold=saved.get("policy_threshold",.95),fixed=fixed)
            state["packets"].append(packet);state["last"]=stamp
            decision=state["detector"].observe(state["packets"])
            if decision is not None:
                stats["decisions"].append(dict(**decision,latency_ms=(time.perf_counter()-state["first_arrival"])*1000))
                completed[key]=(stamp,state["isn"])
                if len(completed)>32768:completed.popitem(last=False)
            else:
                active[key]=state
                if len(active)>8192:active.popitem(last=False);stats.setdefault("censored_capacity",0);stats["censored_capacity"]+=1
            if stats["processed"]%100==0:stats["rss_peak"]=max(stats["rss_peak"],psutil.Process().memory_info().rss)
    finally:stop.set();worker.join(timeout=2)
    if producer_error:raise RuntimeError(producer_error[0])
    elapsed=time.perf_counter()-started;latency=[d["latency_ms"] for d in stats["decisions"]]
    return dict(scope="Original capture pacing at speed=1; arrival queue, parsing, causal features and incremental inference; no NIC or HTTP",
        source=str(Path(path).relative_to(ROOT)),source_sha256=digest(path),checkpoint_sha256=digest(checkpoint),fixed=fixed,speed=speed,clip_seconds=seconds,
        offered=stats["offered"],processed=stats["processed"],queue_drops=stats["dropped_by_queue"],queue_capacity=capacity,queue_peak=stats["queue_peak"],
        elapsed_seconds=elapsed,processed_packets_per_second=stats["processed"]/max(elapsed,1e-9),
        decisions=len(latency),censored_sessions=len(active)+stats.get("censored_at_session_boundary",0)+stats.get("censored_capacity",0),
        latency_ms={str(q):float(np.percentile(latency,q)) if latency else None for q in (50,95,99)},
        inference_ms={str(q):float(np.percentile(stats["inference_ms"],q)) if stats["inference_ms"] else None for q in (50,95,99)},
        mean_packets_to_decision=float(np.mean([d["packets"] for d in stats["decisions"]])) if latency else None,
        inference_calls=stats["inference_calls"],rss_peak_bytes=max(stats["rss_peak"],psutil.Process().memory_info().rss),
        gpu_peak_bytes=torch.cuda.max_memory_allocated() if device=="cuda" else None,
        warning="Latency is conditional on completed decisions; short censored clips do not establish full-capture performance")


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run");parser.add_argument("--seconds",type=float,default=5.)
    parser.add_argument("--device",choices=("cuda","cpu"),default="cuda");args=parser.parse_args()
    if not 0<args.seconds<=30:parser.error("Clip must be 0–30 seconds")
    folder=ROOT/"artifacts/research/runs"/args.run;lock=json.loads((folder/"locked-models.json").read_text())
    entry=next(m for m in lock["models"] if m["name"]=="resnet1d_prefix" and m["seed"]==42)
    checkpoint=folder/entry["path"]
    if digest(checkpoint)!=entry["sha256"]:raise ValueError("Checkpoint changed")
    payload=torch.load(checkpoint,map_location="cpu",weights_only=True);payload["policy_threshold"]=entry["policy"]["threshold"]
    inference_checkpoint=folder/"models/stream-policy.pth";torch.save(payload,inference_checkpoint)
    reports=[];torch.set_num_threads(2)
    for source in ("normal7-behavior","ctu10","cse"):
        for fixed in (None,16):
            report=replay(inference_checkpoint,ROOT/f"data/external/{source}/capture.pcap",args.seconds,1.,256,fixed,args.device)
            reports.append(report);print(source,fixed,report["decisions"],report["latency_ms"],flush=True)
    reports.append(replay(inference_checkpoint,ROOT/"data/external/cse/capture.pcap",args.seconds,100.,8,None,args.device))
    write(folder/"streaming.json",dict(status="measured",reports=reports,real_prevention=False,synthetic_demo_packets=False))


if __name__=="__main__":main()
