"""Ordered post-training measurements, verification, one-time final test and exports."""
import argparse
import json
import subprocess
import sys
import time
from research.dataset import ROOT
from research.run import write


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run");args=parser.parse_args()
    folder=ROOT/"artifacts/research/runs"/args.run
    if not (folder/"locked-models.json").exists() or not (folder/"precision-lock.json").exists():raise ValueError("Training and precision methods must be locked first")
    steps=[("cost","cost.json",[]),("streaming","streaming.json",[]),("verify","verification.json",["--replay"]),
           ("finalize","final-evaluation.json",[]),("report","scorecard.json",[])]
    progress=dict(run_id=args.run,started=time.time(),steps=[])
    for module,output,extra in steps:
        if (folder/output).exists():
            if module=="verify" and json.loads((folder/output).read_text()).get("status")!="passed":raise ValueError("Existing prediction replay verification did not pass")
            progress["steps"].append(dict(stage=module,status="already_recorded"));continue
        progress["current"]=module;write(folder/"pipeline.json",progress)
        result=subprocess.run([sys.executable,"-m","research."+module,args.run,*extra],cwd=ROOT)
        if module=="verify" and result.returncode==0 and json.loads((folder/output).read_text()).get("status")!="passed":
            result.returncode=2
        progress["steps"].append(dict(stage=module,status="passed" if result.returncode==0 else "failed",returncode=result.returncode))
        write(folder/"pipeline.json",progress)
        if result.returncode:raise SystemExit(result.returncode)
    progress["current"]=None;progress["completed"]=time.time();write(folder/"pipeline.json",progress)


if __name__=="__main__":main()
