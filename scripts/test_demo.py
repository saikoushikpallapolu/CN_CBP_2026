"""Reproduce the live app's small real-capture demonstration over HTTP."""
import argparse
import json
import os
from pathlib import Path
import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--output", default="artifacts/demo-report.json")
    parser.add_argument("--verify-upload", action="store_true", help="Compare a sample with the same capture uploaded under a misleading name")
    args = parser.parse_args()
    response = requests.post(args.url.rstrip("/") + "/api/demo", timeout=120,
                             headers={"X-API-Key": os.getenv("TRAFFICSCAN_API_KEY", "")})
    response.raise_for_status()
    report = response.json()
    if args.verify_upload:
        headers = {"X-API-Key": os.getenv("TRAFFICSCAN_API_KEY", "")}
        baseline = requests.post(args.url.rstrip("/") + "/api/analyze/sample", json={"sample_id": "demo-ddos"}, headers=headers, timeout=60)
        baseline.raise_for_status()
        with Path("data/production/samples/demo-ddos.pcap").open("rb") as capture:
            renamed = requests.post(args.url.rstrip("/") + "/api/analyze/upload", headers=headers,
                                    files={"file": ("totally-normal-traffic.pcap", capture, "application/octet-stream")}, timeout=60)
        renamed.raise_for_status()
        first, second = baseline.json(), renamed.json()
        identical = first["counts"] == second["counts"] and len(first["flows"]) == len(second["flows"]) and all(
            a["prediction"] == b["prediction"] and a["fingerprint"] == b["fingerprint"] for a, b in zip(first["flows"], second["flows"]))
        if not identical:
            raise ValueError("Same capture changed predictions when renamed/uploaded")
        report["upload_parity"] = dict(passed=True, uploaded_as="totally-normal-traffic.pcap", counts=second["counts"],
                                       scope="Identical bytes, verdicts and fingerprints; names do not determine predictions")
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    for case in report["cases"]:
        print(case["title"], "flows:", case["flow_count"], "class match:", round(case["class_match_rate"] * 100, 1),
              "% unknown:", round(case["unknown_rate"] * 100, 1), "%")
    print("Evidence:", path)


if __name__ == "__main__":
    main()
