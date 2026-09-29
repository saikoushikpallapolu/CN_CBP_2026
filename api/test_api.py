"""
api/test_api.py - Unit test suite for FastAPI backend endpoints.
"""

from __future__ import annotations

import sys
from pathlib import Path
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.server import app

client = TestClient(app)

def test_endpoints():
    print("[*] Testing GET /api/health ...")
    resp = client.get("/api/health")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    health_data = resp.json()
    print(f"    Status: {health_data.get('status')} | Model: {health_data.get('model')} | Device: {health_data.get('device')}")
    assert health_data["status"] == "online"

    print("\n[*] Testing GET /api/samples ...")
    resp = client.get("/api/samples")
    assert resp.status_code == 200
    samples = resp.json()
    print(f"    Found {len(samples)} demo samples:")
    for s in samples:
        print(f"    - {s['id']}: {s['label']} (Available: {s['available']}, Size: {s['size_mb']} MB)")
    assert len(samples) >= 3

    print("\n[*] Testing POST /api/analyze/sample (ddos) ...")
    resp = client.post("/api/analyze/sample", json={"sample_id": "ddos"})
    assert resp.status_code == 200, f"Error: {resp.text}"
    result = resp.json()
    print(f"    Sample: {result.get('sample_label')}")
    print(f"    Prediction: {result.get('prediction')} ({result.get('confidence_pct')}%)")
    print(f"    Risk Level: {result.get('risk_level')}")
    print(f"    Probabilities: {result.get('probabilities')}")
    print(f"    Image Base64 length: {len(result.get('image_64', ''))} chars")
    assert "image_64" in result
    assert "probabilities" in result

    print("\n[*] Testing POST /api/analyze/upload (with synthetic bytes) ...")
    dummy_payload = b"\x45\x00\x00\x3c" * 1024  # 4096 bytes
    files = {"file": ("test_capture.pcap", dummy_payload, "application/octet-stream")}
    resp = client.post("/api/analyze/upload", files=files)
    assert resp.status_code == 200, f"Error: {resp.text}"
    upload_result = resp.json()
    print(f"    Filename: {upload_result.get('filename')}")
    print(f"    Prediction: {upload_result.get('prediction')} ({upload_result.get('confidence_pct')}%)")
    print(f"    Hex rows returned: {len(upload_result.get('hex_dump', []))}")
    assert upload_result["prediction"] in ["benign", "botnet", "ddos"]

    print("\n[OK] ALL API BACKEND ENDPOINTS PASSED VERIFICATION!")

if __name__ == "__main__":
    test_endpoints()
