"""Additional bounded final sources, acquired before any research model fitting."""
import hashlib
import io
from pathlib import Path
from scripts.acquire_production_data import range_bytes,atomic_bytes,capture_subset,ctu_labels,save_source
from data_processing.production import read_capture


def main():
    root=Path(__file__).resolve().parents[1]
    for name,directory,filename in (("research-normal14","CTU-Normal-14","2017-07-23_capture-winFull.pcap"),
                                     ("research-normal18","CTU-Normal-18","2017-09-05_capture-win4.pcap")):
        folder=root/"data/external"/name;folder.mkdir(parents=True,exist_ok=True)
        if (folder/"source.json").exists():continue
        url=f"https://mcfp.felk.cvut.cz/publicDatasets/{directory}/{filename}"
        _,total=range_bytes(url,0,24);raw,_=range_bytes(url,0,min(total,32*1024**2));stream=io.BytesIO(raw);last=0;stamps=[]
        for stamp,frame,link in read_capture(stream,max_packets=2000000,allow_truncated=len(raw)<total):
            last=stream.tell();stamps.append(stamp)
        if not last:raise ValueError("No complete valid packets")
        payload=raw[:last];atomic_bytes(folder/"capture.pcap",payload)
        save_source(root/"data/external/acquisition.json",name,dict(status="research_reserved_normal",split="final",source_id=directory,
            reference=f"https://mcfp.felk.cvut.cz/publicDatasets/{directory}/",label_policy="Publisher-designated normal; no independent label audit",
            capture=dict(url=url,remote_bytes=total,size=len(payload),sha256=hashlib.sha256(payload).hexdigest(),packets=len(stamps),first_timestamp=min(stamps),last_timestamp=max(stamps),
                         prefix_only=len(payload)<total,timestamps="original, unchanged; relative time allowed for controlled normal labels")))
        print(name,len(stamps),flush=True)
    name="research-ctu13";folder=root/"data/external"/name;folder.mkdir(parents=True,exist_ok=True)
    if not (folder/"source.json").exists():
        base="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/"
        capture=capture_subset(base+"botnet-capture-20110815-fast-flux-2.pcap",folder/"capture.pcap",32,None)
        labels=ctu_labels(base,capture,folder/"labels.csv")
        save_source(root/"data/external/acquisition.json",name,dict(status="research_reserved_labeled",split="final",source_id="ctu13-scenario13",family="Virut",reference=base,capture=capture,labels=labels))
        print("research-ctu13 reserved",flush=True)


if __name__=="__main__":main()
