"""Duration-bound replay audit with RSS telemetry; live corpus supplied explicitly."""
import argparse
import json
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import psutil
from classification.production import FlowClassifier


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("captures", nargs="+")
    parser.add_argument("--hours", type=float, default=24)
    parser.add_argument("--output", default="artifacts/stability.jsonl")
    parser.add_argument("--interval", type=float, default=1., help="Seconds between complete replay cycles")
    args = parser.parse_args()
    if args.hours <= 0 or args.interval < 0:
        parser.error("hours must be positive and interval nonnegative")
    engine = FlowClassifier()
    if not engine.model:
        raise SystemExit("A trained checkpoint is required")
    start = time.monotonic()
    capture_hashes = {}
    for capture in args.captures:
        with Path(capture).open("rb") as source:
            capture_hashes[str(Path(capture).resolve())] = hashlib.file_digest(source, "sha256").hexdigest()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    summary = dict(scope="public/offline dataset replay; no live sensor audit", requested_hours=args.hours,
                   completed=False, iterations=0, failures=0, max_rss_bytes=0,
                   started_at=datetime.now(timezone.utc).isoformat(),
                   checkpoint_sha256=engine.checkpoint_sha256, device=str(engine.device), backend=engine.backend,
                   captures=[str(Path(capture).resolve()) for capture in args.captures], capture_sha256=capture_hashes,
                   telemetry_write_retries=0)
    def save_summary(final=False):
        summary["elapsed_seconds"] = time.monotonic() - start
        summary["completed"] = summary["elapsed_seconds"] >= args.hours * 3600
        summary["passed"] = summary["completed"] and summary["failures"] == 0
        temporary = output.with_suffix(".summary.tmp")
        for attempt in range(6):
            try:
                temporary.write_text(json.dumps(summary, indent=2), encoding="utf-8")
                temporary.replace(output.with_suffix(".summary.json"))
                return
            except PermissionError:
                summary["telemetry_write_retries"] += 1
                time.sleep(min(2., .1 * 2 ** attempt))
        if final:
            raise RuntimeError("Final audit summary could not be committed; inspect the complete JSONL")
        print("Summary file locked; JSONL audit continues; summary update will retry", flush=True)
    save_summary()
    last_summary = time.monotonic()
    with output.open("a", encoding="utf-8", buffering=1) as log:
        while time.monotonic() - start < args.hours * 3600:
            for capture in args.captures:
                record = {"elapsed_seconds": time.monotonic()-start, "rss_bytes": psutil.Process().memory_info().rss, "capture": Path(capture).name}
                try:
                    result = engine.analyze(capture, Path(capture).name)
                    record.update(telemetry=result["telemetry"], counts=result["counts"], success=True)
                except Exception as error:
                    record.update(success=False, error=str(error))
                log.write(json.dumps(record) + "\n")
                summary["iterations"] += 1
                summary["failures"] += not record["success"]
                summary["max_rss_bytes"] = max(summary["max_rss_bytes"], record["rss_bytes"])
                if time.monotonic() - last_summary >= 60:
                    save_summary()
                    last_summary = time.monotonic()
                if time.monotonic() - start >= args.hours * 3600:
                    break
            time.sleep(min(args.interval, max(0, args.hours * 3600 - (time.monotonic() - start))))
    save_summary(final=True)


if __name__ == "__main__":
    main()
