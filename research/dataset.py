"""Causal first-32-packet sessions with source and raw-event provenance."""
import argparse
from collections import OrderedDict, Counter
import hashlib
import json
import struct
from pathlib import Path
import numpy as np
from classification.behavior import BehaviorContext, FEATURES
from data_processing.production import read_capture, parse_packet, packet_features
from data_processing.build_production import FlowLabels
from ml.train_behavior import sources as existing_sources
from research.adaptive import STAGES

ROOT=Path(__file__).resolve().parents[1]


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def session_prefixes(records, labeler, max_active=8192):
    active=OrderedDict(); completed=OrderedDict(); behavior=BehaviorContext(); watermark=0.
    def finish(state, now, reason):
        n=len(state["packets"]); first=state["packets"][0]
        last_features=state["last_features"]
        for i,k in enumerate(STAGES):
            if state["features"][i] is None:
                state["features"][i]=last_features.copy(); state["ready"][i]=max(now,first.timestamp)-first.timestamp
        state["terminal_reason"]=reason
        return state
    for sequence,(stamp,raw,link) in enumerate(records):
        watermark=max(watermark,stamp)
        while active and next(iter(active.values()))["last"]<watermark-30:
            _,expired=active.popitem(last=False)
            yield finish(expired,expired["last"]+30,"idle_timeout")
        packet=parse_packet(raw,stamp,link)
        behavior.observe(packet,stamp,raw,link)
        if packet is None: continue
        syn=packet.protocol==6 and raw[packet.transport_offset+13]&0x12==2
        isn=raw[packet.transport_offset+4:packet.transport_offset+8] if syn else None
        key=packet.key
        done=completed.pop(key,None)
        if done and stamp-done[0]<=30 and (not syn or done[1]==isn):
            completed[key]=(stamp,done[1]);continue
        state=active.pop(key,None)
        if state and (stamp-state["last"]>30 or (syn and state["isn"] is not None and isn!=state["isn"])):
            yield finish(state,watermark,"idle_or_new_session");state=None
        if state is None:
            state=dict(packets=[],truth=[],features=[None]*4,ready=[None]*4,isn=isn,last=stamp,first_sequence=sequence)
        state["packets"].append(packet);state["truth"].append(labeler(packet));state["last"]=stamp
        state["last_features"]=behavior.features(state["packets"][0]).copy()
        n=len(state["packets"])
        if n in STAGES:
            index=STAGES.index(n);state["features"][index]=behavior.features(state["packets"][0]).copy()
            state["ready"][index]=max(watermark,state["packets"][0].timestamp)-state["packets"][0].timestamp
        if n==32:
            yield finish(state,watermark,"max_context")
            completed[key]=(stamp,state["isn"])
            if len(completed)>32768: completed.popitem(last=False)
        else: active[key]=state
        if len(active)>max_active:
            _,old=active.popitem(last=False);yield finish(old,watermark,"capacity_eviction")
    for state in active.values():yield finish(state,watermark,"capture_end")


def registry():
    for name,split,path,labeler in existing_sources():
        yield dict(name=name,split="development" if split in ("test","challenge") else split,path=path,labeler=labeler,
                   group="ctu-win16-20160913" if name=="normal9-behavior" else name,
                   family="benign" if name in ("monday","ctu-normal","normal-dns","normal7-behavior","normal9-behavior") else
                     "HOIC" if name=="cse21-hoic" else "Neris" if name in ("ctu1","ctu2","ctu9") else "Rbot" if name=="ctu10" else name)
    for name in ("research-normal8a","research-normal8b","research-normal13","research-normal14","research-normal18","research-ctu12","research-ctu13"):
        folder=ROOT/"data/external"/name
        if not (folder/"capture.pcap").exists(): continue
        final=name not in ("research-normal8a","research-normal8b")
        if name.startswith("research-ctu"):
            labeler=FlowLabels(folder/"labels.csv");labeler.align_capture_clock(folder/"capture.pcap")
        else: labeler=lambda p:"benign"
        yield dict(name=name,split="final" if final else "development",path=folder/"capture.pcap",labeler=labeler,
                   group="ctu-win16-20160913" if not final else name,family="NSIS.ay" if name=="research-ctu12" else "Virut" if name=="research-ctu13" else "benign")


def build(protocol, output):
    if output.exists(): raise ValueError("Frozen dataset already exists; use a new output path")
    values={key:[] for key in ("masked","unmasked","behavior","length","ready","label","family","source","group","split","session","first_timestamp")}
    audit=[];seen={}; groups={}
    for item in registry():
        name,split,path=item["name"],item["split"],item["path"]
        if item["group"] in groups and groups[item["group"]]!=split: raise ValueError("Capture group crosses partitions")
        groups[item["group"]]=split
        counts=Counter(); accepted=0; excluded=0; max_count=protocol["max_per_source"]
        for session in session_prefixes(read_capture(path,max_packets=protocol["max_packets_per_source"],allow_truncated="slice100MB" in path.name),item["labeler"]):
            truth=set(session["truth"])
            if len(truth)!=1 or None in truth:excluded+=1;continue
            label=truth.pop(); packets=session["packets"];family=item["family"]
            if name in ("cse","cse21"):
                from scripts.prepare_cse import SCHEDULES
                from datetime import datetime
                family=next((f for f,proto,begin,end in SCHEDULES[name] if packets[0].protocol==proto and datetime.fromisoformat(begin).timestamp()<=packets[0].timestamp<=datetime.fromisoformat(end).timestamp()),name)
            if label=="benign":family="benign"
            bucket=(label,family)
            limit=max_count//2 if name=="cse" else max_count
            if counts[bucket]>=limit:continue
            event=hashlib.sha256(b"".join(struct.pack("!dI",p.timestamp,len(p.raw))+p.raw for p in packets)).hexdigest()
            if event in seen:
                if seen[event]!=split: raise ValueError("Exact packet events cross partitions")
                continue
            seen[event]=split
            for key,mask in (("masked",True),("unmasked",False)):
                rows=np.zeros((32,32),dtype=np.uint8)
                for i,p in enumerate(packets):rows[i]=np.frombuffer(packet_features(p,mask=mask),dtype=np.uint8)
                values[key].append(rows)
            values["behavior"].append(np.stack(session["features"]))
            values["ready"].append(session["ready"])
            for key,value in dict(length=len(packets),label=["benign","botnet","ddos"].index(label),family=family,source=name,group=item["group"],split=split,
                                  session=event,first_timestamp=packets[0].timestamp).items():values[key].append(value)
            counts[bucket]+=1;accepted+=1
            if name!="cse" and accepted>=max_count:break
        record=dict(source=name,group=item["group"],split=split,accepted=accepted,excluded=excluded,sha256=digest(path),classes={str(k):v for k,v in counts.items()})
        if path.with_name("labels.csv").exists():record["label_sha256"]=digest(path.with_name("labels.csv"))
        if isinstance(item["labeler"],FlowLabels):record["clock_alignment"]=item["labeler"].clock_evidence
        audit.append(record);print(name,split,accepted,flush=True)
    if not values["label"]:raise ValueError("No labeled data")
    data={key:np.asarray(value) for key,value in values.items()}
    if not set(protocol["final_holdout_sources"])<=set(data["source"][data["split"]=="final"]):raise ValueError("Reserved final source missing or has no confirmed sessions")
    for split in ("train","validation","development","final"):
        if not (data["split"]==split).any():raise ValueError("Required partition missing: "+split)
    if not {0,1,2}<=set(data["label"][data["split"]=="train"]):raise ValueError("Training classes incomplete")
    output.parent.mkdir(parents=True,exist_ok=True);np.savez_compressed(output,**data)
    manifest=dict(version="research-prefix-v1",sources=audit,n=len(data["label"]),dataset_sha256=digest(output),protocol_sha256=digest(ROOT/"research/protocol.json"),
                  stages=list(STAGES),behavior_features=FEATURES,
                  synthetic_packets=False,session_policy="First32, 30s idle, SYN ISN boundary; max8192 active; exact raw-event cross-split audit",
                  sampling_policy="First confirmed sessions per bounded source/family; not a representative population sample",
                  limitations=["Small public subsets; publisher/schedule labels still need independent audit","Previously inspected sources are development evidence","No per-application ground truth for mixed normal traces", "Final normal and attack sources remain small"],
                  counts={split:int((data["split"]==split).sum()) for split in np.unique(data["split"])})
    output.with_suffix(".json").write_text(json.dumps(manifest,indent=2));print(json.dumps(manifest["counts"]),flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--output",default="artifacts/research/frozen-v1.npz");args=parser.parse_args()
    build(json.loads((ROOT/"research/protocol.json").read_text()),ROOT/args.output)
