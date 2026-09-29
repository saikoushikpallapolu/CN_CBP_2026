"""
api/server.py - FastAPI Backend Service for PCAP-to-Image Malware Fingerprinting.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from classification.infer import get_classifier

app = FastAPI(
    title="TrafficScan AI - PCAP Fingerprint API",
    description="Real-time Network Packet Capture to 2D Grayscale Image Malware Classification",
    version="1.0.0"
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Predefined samples available in data/raw
DEMO_SAMPLES = [
    {
        "id": "benign",
        "label": "Benign Traffic",
        "subtitle": "Normal Office Network Activity (CIC-IDS2017 Monday)",
        "path": "data/raw/benign/Monday-WorkingHours_slice100MB.pcap",
        "type": "pcap"
    },
    {
        "id": "ddos",
        "label": "DDoS Traffic",
        "subtitle": "High-Volume Denial of Service Attack (Wednesday)",
        "path": "data/raw/ddos/Wednesday-workingHours_slice100MB.pcap",
        "type": "pcap"
    },
    {
        "id": "botnet",
        "label": "Botnet Traffic",
        "subtitle": "ARES Botnet Command & Control Activity (Friday)",
        "path": "data/raw/botnet/Friday-WorkingHours_slice100MB.pcap",
        "type": "pcap"
    }
]


class SampleAnalyzeRequest(BaseModel):
    sample_id: str


@app.get("/api/health")
def health_check() -> dict[str, Any]:
    """Health check endpoint to verify API and model readiness."""
    try:
        classifier = get_classifier()
        return {
            "status": "online",
            "model": "TrafficCNN (3 Conv + 2 Linear)",
            "classes": classifier.classes,
            "device": str(classifier.device),
            "checkpoint": str(classifier.checkpoint_path.name)
        }
    except Exception as e:
        return {
            "status": "degraded",
            "error": str(e)
        }


@app.get("/api/samples")
def get_sample_files() -> list[dict[str, Any]]:
    """Return list of available demo sample PCAP files."""
    results = []
    for s in DEMO_SAMPLES:
        abs_path = PROJECT_ROOT / s["path"]
        exists = abs_path.is_file()
        size_mb = round(abs_path.stat().st_size / (1024 * 1024), 2) if exists else 0
        results.append({
            "id": s["id"],
            "label": s["label"],
            "subtitle": s["subtitle"],
            "filename": abs_path.name,
            "size_mb": size_mb,
            "available": exists
        })
    return results


@app.post("/api/analyze/sample")
def analyze_sample(req: SampleAnalyzeRequest) -> dict[str, Any]:
    """Run malware fingerprinting on one of the preloaded demo samples."""
    sample = next((s for s in DEMO_SAMPLES if s["id"] == req.sample_id), None)
    if not sample:
        raise HTTPException(status_code=404, detail=f"Sample '{req.sample_id}' not found.")

    target_path = PROJECT_ROOT / sample["path"]
    if not target_path.is_file():
        raise HTTPException(status_code=404, detail=f"Sample file not found on disk: {target_path}")

    try:
        classifier = get_classifier()
        res = classifier.predict_pcap_file(target_path, max_bytes=4096)
        res["source_type"] = "sample"
        res["sample_id"] = sample["id"]
        res["sample_label"] = sample["label"]
        res["filename"] = target_path.name
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")


@app.post("/api/analyze/upload")
async def analyze_uploaded_file(file: UploadFile = File(...)) -> dict[str, Any]:
    """Run malware fingerprinting on a user-uploaded PCAP or Image file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file missing filename.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        classifier = get_classifier()
        res = classifier.predict_uploaded_file(content, file.filename)
        res["source_type"] = "upload"
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process uploaded file: {str(e)}")


# Serve static web frontend if the frontend directory exists
FRONTEND_DIR = PROJECT_ROOT / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_frontend_index():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))
        return {"message": "Frontend directory found, but index.html missing."}


if __name__ == "__main__":
    import uvicorn
    print("\n[+] Starting TrafficScan AI API server on http://127.0.0.1:8000 ...")
    uvicorn.run("api.server:app", host="127.0.0.1", port=8000, reload=True)
