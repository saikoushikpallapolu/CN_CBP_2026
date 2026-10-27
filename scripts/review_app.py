"""Start/stop the localhost-only GPU review app with persistent investigations."""
import argparse
import json
import re
import subprocess
import time
from pathlib import Path
import requests

NAME = "trafficscan-review"
LABEL = "com.trafficscan.review"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "stop", "status"), default="start", nargs="?")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--model", default="candidate_flow_resnet")
    parser.add_argument("--recreate", action="store_true", help="Replace only the labeled review container; preserve its bound history")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not re.fullmatch(r"[A-Za-z0-9_]+", args.model):
        parser.error("Use a port from 1024–65535 and a checkpoint basename")
    root = Path(__file__).resolve().parents[1]
    existing = subprocess.run(["docker", "inspect", NAME], capture_output=True, text=True)
    container = json.loads(existing.stdout)[0] if existing.returncode == 0 else None
    if container and (container["Config"]["Labels"] or {}).get(LABEL) != "true":
        raise SystemExit("Container name belongs to another service; no changes made")
    if args.action == "stop":
        if container:
            subprocess.run(["docker", "stop", NAME], check=True)
        return
    if args.action == "status":
        print(json.dumps(dict(exists=bool(container), running=bool(container and container["State"]["Running"])), indent=2))
        return
    if container and args.recreate:
        subprocess.run(["docker", "stop", NAME], check=True, capture_output=True)
        subprocess.run(["docker", "rm", NAME], check=True, capture_output=True)
        container = None
    if container:
        subprocess.run(["docker", "start", NAME], check=True, capture_output=True)
        bindings = container["HostConfig"]["PortBindings"]["8000/tcp"]
        args.port = int(bindings[0]["HostPort"])
    else:
        prefix = root / "ml/checkpoints" / args.model
        for suffix in (".pth", ".engine", ".engine.json", ".engine.audit.json"):
            if not prefix.with_name(prefix.name + suffix).is_file():
                raise SystemExit("Missing reviewed artifact: " + str(prefix) + suffix)
        evidence = root / "artifacts/review"
        evidence.mkdir(parents=True, exist_ok=True)
        command = ["docker", "run", "-d", "--name", NAME, "--label", LABEL + "=true",
                   "--restart", "unless-stopped", "--gpus", "all", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges:true", "--memory=4g", "--cpus=4",
                   "--tmpfs", "/tmp:rw,size=134217728,mode=1777", "-p", f"127.0.0.1:{args.port}:8000",
                   "-e", f"TRAFFICSCAN_CHECKPOINT=/app/ml/checkpoints/{args.model}.pth",
                   "-e", f"TRAFFICSCAN_TENSORRT=/app/ml/checkpoints/{args.model}.engine",
                   "-e", "TRAFFICSCAN_DB=/app/review/investigations.sqlite3",
                   "-e", "TRAFFICSCAN_REQUIRE_READY=0"]
        for source, target, readonly in (("ml/checkpoints", "/app/ml/checkpoints", True),
                                         ("data/production", "/app/data/production", True),
                                         ("data/external", "/app/data/external", True),
                                         ("artifacts/review", "/app/review", False)):
            command.extend(["--mount", f"type=bind,source={root / source},target={target}" + (",readonly" if readonly else "")])
        command.append("trafficscan:gpu")
        subprocess.run(command, check=True, capture_output=True, text=True)
    url = f"http://127.0.0.1:{args.port}"
    for attempt in range(45):
        try:
            state = requests.get(url + "/api/health", timeout=3).json()
            if state.get("status") == "online" and state.get("backend") == "tensorrt" and state.get("runtime_report"):
                print(json.dumps(dict(url=url, backend=state["backend"], device=state["device"],
                                     production_ready=state["production_ready"], mode="experimental review"), indent=2))
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise SystemExit("Review service did not become healthy; inspect docker logs " + NAME)


if __name__ == "__main__":
    main()
