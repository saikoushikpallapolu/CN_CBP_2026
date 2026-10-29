"""TrafficScan investigation API. Use an authenticated TLS proxy publicly."""
from __future__ import annotations
import hmac
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from classification.production import ROOT, get_flow_classifier
from api.body_limit import UploadBodyLimit

app = FastAPI(title="TrafficScan API", version="2.0.0")
MAX_UPLOAD = int(os.getenv("TRAFFICSCAN_MAX_UPLOAD_MB", "64")) * 1024 ** 2
app.add_middleware(UploadBodyLimit, limit=MAX_UPLOAD + 1024 * 1024)
DB_PATH = Path(os.getenv("TRAFFICSCAN_DB", str(ROOT / "data/production/investigations.sqlite3")))
ANALYSIS_SLOT = threading.BoundedSemaphore(1)
SAMPLES = {
    "monday": ("Monday · normal baseline", "data/production/samples/monday.pcap"),
    "ctu1": ("CTU-13 · scenario 1", "data/production/samples/ctu1.pcap"),
    "friday": ("Friday · attack window", "data/production/samples/friday.pcap"),
    "cse": ("CSE 2018 · LOIC attack window", "data/production/samples/cse.pcap"),
    "mawi": ("MAWI · unlabeled backbone", "data/production/samples/mawi.pcap"),
    "demo-normal": ("Demo · labeled normal traffic", "data/production/samples/demo-normal.pcap"),
    "demo-botnet": ("Demo · labeled botnet", "data/production/samples/demo-botnet.pcap"),
    "demo-ddos": ("Demo · labeled DDoS", "data/production/samples/demo-ddos.pcap"),
    "demo-unseen": ("Demo · unseen HOIC / review", "data/production/samples/demo-unseen.pcap"),
}

def authorize(x_api_key: str | None = Header(default=None)):
    expected = os.getenv("TRAFFICSCAN_API_KEY")
    if expected and not hmac.compare_digest(x_api_key or "", expected):
        raise HTTPException(401, "Valid API key required")

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.execute("CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, created_at TEXT, filename TEXT, prediction TEXT, payload TEXT, summary TEXT)")
    if "summary" not in {row[1] for row in connection.execute("PRAGMA table_info(investigations)")}:
        connection.execute("ALTER TABLE investigations ADD COLUMN summary TEXT")
    return connection

def save(result):
    result["id"] = uuid.uuid4().hex
    result["created_at"] = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        summary = json.dumps({"telemetry": result["telemetry"], "counts": result["counts"]})
        db.execute("INSERT INTO investigations (id,created_at,filename,prediction,payload,summary) VALUES (?, ?, ?, ?, ?, ?)", (result["id"], result["created_at"], result["filename"], result["prediction"], json.dumps(result), summary))
        db.execute("DELETE FROM investigations WHERE id NOT IN (SELECT id FROM investigations ORDER BY created_at DESC LIMIT 100)")
    return result

def analyze(source, filename, truncated=False, reserved=False):
    if not reserved and not ANALYSIS_SLOT.acquire(blocking=False):
        raise HTTPException(429, "Analysis in progress. Retry shortly.")
    try:
        return save(get_flow_classifier().analyze(source, filename, truncated))
    except (ValueError, OSError) as error:
        raise HTTPException(422, str(error)) from error
    finally:
        if not reserved:
            ANALYSIS_SLOT.release()

@app.middleware("http")
async def security_headers(request, call_next):
    if request.url.path.startswith("/api/") and request.url.path not in ("/api/health", "/api/ready"):
        expected = os.getenv("TRAFFICSCAN_API_KEY")
        if expected and not hmac.compare_digest(request.headers.get("x-api-key", ""), expected):
            return JSONResponse({"detail": "Valid API key required"}, status_code=401)
    if request.url.path == "/api/analyze/upload":
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > MAX_UPLOAD + 1024 * 1024):
            return JSONResponse({"detail": "Upload exceeds request size limit"}, status_code=413)
    upload_request = request.method == "POST" and request.url.path == "/api/analyze/upload"
    if upload_request and not ANALYSIS_SLOT.acquire(blocking=False):
        return JSONResponse({"detail": "Analysis in progress. Retry shortly."}, status_code=429)
    try:
        response = await call_next(request)
    finally:
        if upload_request:
            ANALYSIS_SLOT.release()
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    if request.url.path in ("/docs", "/redoc"):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif request.url.path == "/" or request.url.path.startswith("/static/"):
        # Revalidate the page and its scripts together after a local redeploy.
        response.headers["Cache-Control"] = "no-cache"
    return response

@app.get("/api/health")
def health():
    state = get_flow_classifier().health()
    return {**state, "report": {k: v for k, v in state["report"].items() if k != "history"}, "authentication_required": bool(os.getenv("TRAFFICSCAN_API_KEY")), "max_upload_mb": MAX_UPLOAD // 1024 ** 2}

@app.get("/api/ready")
def readiness():
    state = get_flow_classifier().health()
    return JSONResponse({"ready": state["production_ready"], "gates": state["report"].get("gates", {}), "model_available": state["status"] == "online"}, status_code=200 if state["production_ready"] else 503)

@app.get("/api/data", dependencies=[Depends(authorize)])
def data_status():
    path = ROOT / "data/external/acquisition.json"
    from scripts.acquire_production_data import load_manifest
    return load_manifest(path)

@app.get("/api/samples", dependencies=[Depends(authorize)])
def samples():
    return [dict(id=key, label=label, filename=Path(path).name, available=(ROOT / path).is_file()) for key, (label, path) in SAMPLES.items()]

class SampleRequest(BaseModel):
    sample_id: str


class SimulationRequest(BaseModel):
    scenario: str = "mixed"
    address: str = "192.0.2.10"


@app.post("/api/simulate", dependencies=[Depends(authorize)])
def simulate(request: SimulationRequest):
    from classification.simulation import virtual_capture, VIRTUAL_SENSOR
    if request.address != VIRTUAL_SENSOR:
        raise HTTPException(422, "This virtual sensor uses 192.0.2.10. Other IPs can be focused inside an uploaded capture.")
    if not ANALYSIS_SLOT.acquire(blocking=False):
        raise HTTPException(429, "Analysis in progress. Retry shortly.")
    try:
        capture, metadata = virtual_capture(ROOT, request.scenario)
        with capture:
            result = get_flow_classifier().analyze(capture, "virtual-" + request.scenario + ".pcap")
        result["simulation"] = metadata
        return save(result)
    except (ValueError, OSError) as error:
        raise HTTPException(422, str(error)) from error
    finally:
        ANALYSIS_SLOT.release()


@app.post("/api/demo", dependencies=[Depends(authorize)])
def demonstration():
    from classification.demo import load_cases, compare_case
    if not ANALYSIS_SLOT.acquire(blocking=False):
        raise HTTPException(429, "Analysis in progress. Retry shortly.")
    try:
        manifest = load_cases(ROOT)
        engine = get_flow_classifier()
        results = []
        for case in manifest["cases"]:
            path = ROOT / "data/production/samples" / (case["id"] + ".pcap")
            # Ground truth never enters the classifier or changes its verdict.
            results.append(compare_case(case, engine.analyze(path, path.name)))
        return dict(scope="Small public recorded-capture demo; not a full accuracy benchmark or live traffic test",
                    model=engine.health(), selection=manifest["selection"], cases=results)
    except (ValueError, OSError) as error:
        raise HTTPException(422, str(error)) from error
    finally:
        ANALYSIS_SLOT.release()

@app.post("/api/analyze/sample", dependencies=[Depends(authorize)])
def sample(request: SampleRequest):
    if request.sample_id not in SAMPLES:
        raise HTTPException(404, "Unknown sample")
    _, path = SAMPLES[request.sample_id]
    target = ROOT / path
    if not target.is_file():
        raise HTTPException(404, "Sample not acquired")
    return analyze(target, target.name)

@app.post("/api/analyze/upload", dependencies=[Depends(authorize)])
def upload(file: UploadFile = File(...)):
    try:
        filename = Path((file.filename or "").replace("\\", "/")).name
        if Path(filename).suffix.lower() not in (".pcap", ".pcapng", ".cap"):
            raise HTTPException(415, "Upload a PCAP or PCAPNG capture")
        file.file.seek(0, 2)
        size = file.file.tell()
        if size > MAX_UPLOAD:
            raise HTTPException(413, f"Capture exceeds {MAX_UPLOAD // 1024 ** 2} MB")
        if not size:
            raise HTTPException(400, "Capture is empty")
        file.file.seek(0)
        return analyze(file.file, filename, reserved=True)
    finally:
        file.file.close()

@app.get("/api/investigations", dependencies=[Depends(authorize)])
def investigations():
    with connect() as db:
        rows = db.execute("SELECT id,created_at,filename,prediction,COALESCE(summary,json_object('telemetry',json_extract(payload,'$.telemetry'),'counts',json_extract(payload,'$.counts'))) FROM investigations ORDER BY created_at DESC LIMIT 100").fetchall()
    return [dict(id=row[0], created_at=row[1], filename=row[2], prediction=row[3], **json.loads(row[4])) for row in rows]

@app.get("/api/investigations/{identifier}", dependencies=[Depends(authorize)])
def investigation(identifier: str):
    with connect() as db:
        row = db.execute("SELECT payload FROM investigations WHERE id=?", (identifier,)).fetchone()
    if not row:
        raise HTTPException(404, "Investigation not found")
    return json.loads(row[0])

app.mount("/static", StaticFiles(directory=ROOT / "frontend"), name="static")
@app.get("/")
def index():
    return FileResponse(ROOT / "frontend/index.html")
