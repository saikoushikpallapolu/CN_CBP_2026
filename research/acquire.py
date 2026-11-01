"""Acquire bounded public research inputs without fetching malware binaries."""
import hashlib
import json
import re
from pathlib import Path
import requests
import io
from scripts.acquire_production_data import capture_subset, ctu_labels, save_source
from scripts.acquire_production_data import range_bytes, atomic_bytes
from data_processing.production import read_capture


def main():
    root=Path(__file__).resolve().parents[1]
    folder=root/"data/external/research-ctu12"; folder.mkdir(parents=True,exist_ok=True)
    base="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-53/"
    meta=folder/"source.json"
    if not meta.exists():
        capture=capture_subset(base+"botnet-capture-20110819-bot.pcap",folder/"capture.pcap",32,None)
        labels=ctu_labels(base,capture,folder/"labels.csv")
        report=dict(status="research_reserved_labeled",source_id="ctu13-scenario12",family="NSIS.ay",split="final",
                    reference=base,capture=capture,labels=labels,
                    exclusion="Never fit model, temperature, policy, or anomaly threshold on this source")
        save_source(root/"data/external/acquisition.json","research-ctu12",report)
        print("Acquired reserved NSIS.ay capture and interval labels",flush=True)
    else: print("Reserved capture preserved",flush=True)
    for name,directory,filename,split in (
        ("research-normal8a","CTU-Normal-8-1","2016-09-13_win16.pcap","development"),
        ("research-normal8b","CTU-Normal-8-2","2016-09-13_win16.pcap","development"),
        ("research-normal13","CTU-Normal-13","2017-07-03_capture-win2.pcap","final")):
        target=root/"data/external"/name;target.mkdir(parents=True,exist_ok=True)
        if (target/"source.json").exists():continue
        url=f"https://mcfp.felk.cvut.cz/publicDatasets/{directory}/{filename}"
        _,size=range_bytes(url,0,24)
        if size>2*1024**2:raise ValueError("Expected small complete normal capture")
        payload,_=range_bytes(url,0,size);records=list(read_capture(io.BytesIO(payload)))
        if not records:raise ValueError("Empty capture")
        atomic_bytes(target/"capture.pcap",payload)
        save_source(root/"data/external/acquisition.json",name,dict(status="research_reserved_normal",split=split,
            source_id=directory,reference=f"https://mcfp.felk.cvut.cz/publicDatasets/{directory}/",
            label_policy="Publisher-designated controlled normal; not independently audited",timestamp_policy="Original timestamps unchanged, including relative time",
            capture=dict(url=url,size=size,sha256=hashlib.sha256(payload).hexdigest(),packets=len(records),first_timestamp=records[0][0],last_timestamp=records[-1][0])))
        print("Acquired",name,split,len(records),flush=True)
    # Pinned author implementation, MIT license preserved. No data.zip or PDFs.
    api=requests.get("https://api.github.com/repos/ymirsky/KitNET-py/commits/master",timeout=30);api.raise_for_status()
    commit=api.json()["sha"]
    vendor=root/"research/vendor/kitnet"; vendor.mkdir(parents=True,exist_ok=True)
    manifest=vendor/"UPSTREAM.json"
    if not manifest.exists():
        records={}
        for name in ("KitNET.py","dA.py","corClust.py","utils.py","LICENSE.txt"):
            url=f"https://raw.githubusercontent.com/ymirsky/KitNET-py/{commit}/{name}"
            response=requests.get(url,timeout=30);response.raise_for_status(); original=response.content
            text=original.decode("utf-8")
            if name.endswith(".py"):
                text=re.sub(r"^import dA as AE", "from . import dA as AE",text,flags=re.M)
                text=re.sub(r"^import corClust as CC", "from . import corClust as CC",text,flags=re.M)
                text=re.sub(r"^import utils", "from . import utils",text,flags=re.M)
                text=re.sub(r"^from utils import", "from .utils import",text,flags=re.M)
                text=text.replace("numpy.Inf","numpy.inf")
            (vendor/name).write_text(text,encoding="utf-8")
            records[name]=dict(url=url,original_sha256=hashlib.sha256(original).hexdigest(),local_sha256=hashlib.sha256((vendor/name).read_bytes()).hexdigest())
        (vendor/"__init__.py").write_text('"""Author KitNET implementation; see LICENSE.txt and UPSTREAM.json."""\n')
        manifest.write_text(json.dumps(dict(repository="https://github.com/ymirsky/KitNET-py",commit=commit,
                    patches="Relative imports and NumPy2 Inf→inf compatibility only; feature adapter is separate, not original Kitsune extractor",files=records),indent=2))
    print("KitNET author implementation pinned",flush=True)


if __name__=="__main__":main()
