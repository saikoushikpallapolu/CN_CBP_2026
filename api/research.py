"""Authenticated read-only research registry; never runs training or loads models."""
import hashlib
import json
import os
import re
from pathlib import Path
from fastapi import Depends,HTTPException
from fastapi.responses import FileResponse

EXPORTS={"results.csv","accuracy-delay.svg","risk-coverage.svg","false-alerts.svg","summary.json","final-evaluation.json", "frozen-config.json",
         "scorecard.json","streaming.json","precision.json","verification.json","reproduction-checklist.json","precision.svg",
         "accuracy-delay.png","risk-coverage.png","false-alerts.png","precision.png","cost.json"}


def install_research_routes(app,authorize):
    root=Path(os.getenv("TRAFFICSCAN_RESEARCH_ROOT",str(Path(__file__).resolve().parents[1]/"artifacts/research")))
    def folder(run):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}",run):raise HTTPException(422,"Invalid experiment ID")
        target=(root/"runs"/run).resolve()
        if not target.is_relative_to((root/"runs").resolve()) or not target.is_dir():raise HTTPException(404,"Experiment not found")
        return target
    def read(path):
        if not path.resolve().is_relative_to(root.resolve()):raise HTTPException(404,"Research report unavailable")
        if not path.exists():return None
        if path.stat().st_size>12*1024**2:raise HTTPException(413,"Research report exceeds size limit")
        try:return json.loads(path.read_text())
        except (OSError,ValueError):raise HTTPException(422,"Invalid research report")
    @app.get("/api/research/runs",dependencies=[Depends(authorize)])
    def runs():
        entries=[]
        for path in sorted((root/"runs").glob("*"),reverse=True)[:50]:
            if not path.is_dir() or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}",path.name):continue
            summary=read(path/"summary.json") or {};frozen=read(path/"frozen-config.json") or {}
            entries.append(dict(id=path.name,status=summary.get("status","initializing"),current=summary.get("current"),seed=summary.get("seed"),epoch=summary.get("epoch"),
                                results=len(summary.get("results",[])),created_at=frozen.get("created_at"),dataset_sha256=frozen.get("dataset",{}).get("dataset_sha256")))
        return dict(runs=entries,read_only=True,scope="Research experiments; serving model is unchanged")
    @app.get("/api/research/runs/{run}",dependencies=[Depends(authorize)])
    def detail(run:str):
        path=folder(run)
        return dict(id=run,frozen=read(path/"frozen-config.json"),summary=read(path/"summary.json"),final=read(path/"final-evaluation.json"),
                    precision=read(path/"precision.json"),streaming=read(path/"streaming.json"),scorecard=read(path/"scorecard.json"),
                    exports=sorted(name for name in EXPORTS if (path/name).is_file()))
    @app.get("/api/research/runs/{run}/files/{filename}",dependencies=[Depends(authorize)])
    def export(run:str,filename:str):
        if filename not in EXPORTS:raise HTTPException(404,"Export unavailable")
        target=folder(run);path=(target/filename).resolve()
        if not path.is_relative_to(target):raise HTTPException(404,"Export unavailable")
        if not path.is_file():raise HTTPException(404,"Export unavailable")
        return FileResponse(path,filename=filename)
