"""Bounded official normal captures; the new browsing source is test-only."""
import argparse
import io
import hashlib
import json
from pathlib import Path
from scripts.acquire_production_data import capture_subset, save_source, range_bytes, atomic_bytes
from data_processing.production import read_capture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mib", type=int, default=64)
    args = parser.parse_args()
    if not 1 <= args.mib <= 128: parser.error("mib must be 1–128")
    cases = [("normal7-behavior", "CTU-Normal-7", "2013-12-17_capture1.pcap", "train"),
             ("normal9-behavior", "CTU-Normal-9", "2016-09-13_win16.pcap", "test")]
    for name, directory, filename, split in cases:
        folder = Path("data/external") / name
        if (folder / "source.json").exists():
            print("Existing source preserved", name, flush=True); continue
        folder.mkdir(parents=True, exist_ok=True)
        url = f"https://mcfp.felk.cvut.cz/publicDatasets/{directory}/{filename}"
        if directory == "CTU-Normal-9":
            # This complete small publisher capture uses relative timestamps.
            # Preserve them exactly: controlled-normal labels need no epoch join.
            _, total = range_bytes(url, 0, 24)
            if total > 2 * 1024 ** 2: raise ValueError("Browsing capture exceeds expected bound")
            raw, _ = range_bytes(url, 0, total)
            records = list(read_capture(io.BytesIO(raw)))
            if not records: raise ValueError("Empty normal browsing capture")
            atomic_bytes(folder / "capture.pcap", raw)
            capture = dict(url=url, remote_bytes=total, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                           first_timestamp=records[0][0], last_timestamp=records[-1][0], packets=len(records),
                           timestamp_basis="Original relative seconds, unchanged; no cross-source timestamp joins")
        else:
            capture = capture_subset(url, folder / "capture.pcap", args.mib, None)
        report = dict(status="behavior_controlled_normal", split=split, source_id=directory, capture=capture,
                      reference=f"https://mcfp.felk.cvut.cz/publicDatasets/{directory}/",
                      label_policy="Publisher-designated normal traffic; not independently enterprise-audited")
        save_source(Path("data/external/acquisition.json"), name, report)
        print(name, json.dumps(report), flush=True)


if __name__ == "__main__": main()
