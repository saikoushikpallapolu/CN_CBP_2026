"""Exercise the hardened production image over HTTP, then remove its container."""
import json
import secrets
import subprocess
import time
import argparse
import re
from pathlib import Path
import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gpu", action="store_true")
    parser.add_argument("--model", default="flow_resnet")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_]+", args.model):
        parser.error("model must be a checkpoint basename")
    root = Path(__file__).resolve().parents[1]
    name = "trafficscan-smoke-" + secrets.token_hex(4)
    key = secrets.token_urlsafe(24)
    command = ["docker", "run", "-d", "--rm", "--name", name,
               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
               "--memory=" + ("4g" if args.gpu else "2g"), "--cpus=4", "--tmpfs", "/tmp:rw,size=134217728,mode=1777",
               "-p", "127.0.0.1::8000", "-e", "TRAFFICSCAN_API_KEY=" + key,
               "-e", "TRAFFICSCAN_REQUIRE_READY=1", "-e", "TRAFFICSCAN_DB=/tmp/investigations.sqlite3",
               "--mount", f"type=bind,source={root / 'ml/checkpoints'},target=/app/ml/checkpoints,readonly",
               "--mount", f"type=bind,source={root / 'data/production/samples'},target=/app/data/production/samples,readonly"]
    image = "trafficscan:gpu" if args.gpu else "trafficscan:production"
    if args.gpu:
        prefix = "/app/ml/checkpoints/" + args.model
        command.extend(["--gpus", "all", "-e", "TRAFFICSCAN_CHECKPOINT=" + prefix + ".pth",
                        "-e", "TRAFFICSCAN_TENSORRT=" + prefix + ".engine"])
    command.append(image)
    checks = {}
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        port = subprocess.check_output(["docker", "port", name, "8000"], text=True).strip().rsplit(":", 1)[1]
        base = "http://127.0.0.1:" + port
        for attempt in range(60):
            try:
                if requests.get(base + "/api/health", timeout=2).status_code == 200:
                    break
            except requests.RequestException:
                pass
            time.sleep(1)
        health = requests.get(base + "/api/health", timeout=10)
        checks["health"] = health.status_code == 200 and health.json()["status"] == "online"
        if args.gpu:
            checks["gpu_runtime_verified"] = health.json().get("backend") == "tensorrt" and bool(health.json().get("runtime_report"))
        checks["readiness_enforced"] = requests.get(base + "/api/ready", timeout=10).status_code == 503
        checks["unauthorized_blocked"] = requests.get(base + "/api/samples", timeout=10).status_code == 401
        headers = {"x-api-key": key}
        checks["authorized_samples"] = requests.get(base + "/api/samples", headers=headers, timeout=10).status_code == 200
        response = requests.post(base + "/api/analyze/sample", headers=headers, json={"sample_id": "monday"}, timeout=60)
        payload = response.json()
        checks["sample_analysis"] = response.status_code == 200
        checks["failed_gates_force_unknown"] = bool(payload.get("flows")) and all(flow["prediction"] == "unknown" for flow in payload["flows"])
        checks["history_saved"] = requests.get(base + "/api/investigations", headers=headers, timeout=10).status_code == 200
        page = requests.get(base, timeout=10)
        checks["frontend_and_security_headers"] = page.status_code == 200 and "Content-Security-Policy" in page.headers
        destination = root / ("artifacts/deployment-smoke-gpu.json" if args.gpu else "artifacts/deployment-smoke.json")
        destination.write_text(json.dumps(dict(image=image, checks=checks, passed=all(checks.values())), indent=2))
        print(destination.read_text())
        if not all(checks.values()):
            raise SystemExit("Deployment smoke checks failed")
    finally:
        subprocess.run(["docker", "stop", name], capture_output=True, text=True)


if __name__ == "__main__":
    main()
