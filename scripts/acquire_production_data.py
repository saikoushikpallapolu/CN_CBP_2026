"""Bounded, auditable HTTPS acquisition. Never downloads malware executables.

PCAP ranges retain only whole records. Flow label files are streamed and reduced
to the acquired capture's time interval. Unknown/background traffic stays unknown.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import gzip
import io
import json
import re
import struct
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from zoneinfo import ZoneInfo
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data_processing.production import read_capture
_sessions = threading.local()


def get(url, **kwargs):
    bounded_range = kwargs.pop("bounded_range", False)
    if bounded_range:
        if not hasattr(_sessions, "range_http"):
            _sessions.range_http = requests.Session()
            _sessions.range_http.mount("https://", HTTPAdapter(max_retries=0))
        response = _sessions.range_http.get(url, timeout=(10, 20), **kwargs)
        try:
            response.raise_for_status()
        except requests.RequestException:
            response.close()
            raise
        return response
    if not hasattr(_sessions, "http"):
        _sessions.http = requests.Session()
        retry = Retry(total=3, connect=3, read=3, status=3, backoff_factor=.5,
                      status_forcelist=(429, 500, 502, 503, 504), allowed_methods=("GET",))
        _sessions.http.mount("https://", HTTPAdapter(max_retries=retry))
    response = _sessions.http.get(url, timeout=(20, 45), **kwargs)
    response.raise_for_status()
    return response


def atomic_bytes(path, payload):
    temporary = path.with_suffix(path.suffix + ".part")
    temporary.write_bytes(payload)
    temporary.replace(path)


def atomic_json(path, payload):
    atomic_bytes(path, json.dumps(payload, indent=2).encode("utf-8"))


def load_manifest(path):
    manifest = json.loads(path.read_text()) if path.exists() else {}
    for status in path.parent.glob("*/source.json"):
        manifest[status.parent.name] = json.loads(status.read_text())
    return manifest


def save_source(path, name, metadata):
    # Per-source records remain authoritative even if independent jobs finish
    # together; a central manifest snapshot cannot erase another source's work.
    folder = path.parent / name
    folder.mkdir(parents=True, exist_ok=True)
    atomic_json(folder / "source.json", metadata)
    manifest = load_manifest(path)
    manifest[name] = metadata
    atomic_json(path, manifest)


def range_bytes(url, start, length):
    # urllib3 retries response headers; interrupted streamed bodies also need
    # a whole-range retry before callers append anything to their artifacts.
    for attempt in range(4):
        try:
            endpoint = url
            if attempt % 2 and url.startswith("https://cse-cic-ids2018.s3.amazonaws.com/"):
                endpoint = url.replace("cse-cic-ids2018.s3.amazonaws.com", "cse-cic-ids2018.s3.ca-central-1.amazonaws.com", 1)
            return _range_bytes(endpoint, start, length)
        except requests.RequestException:
            if attempt == 3:
                raise
            time.sleep(.5 * 2 ** attempt)


def _range_bytes(url, start, length):
    if start < 0 or length <= 0:
        raise ValueError("Range start and length must be nonnegative/positive")
    if length > 1024 ** 2:
        chunks = [(offset, min(1024 ** 2, start + length - offset)) for offset in range(start, start + length, 1024 ** 2)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            parts = list(pool.map(lambda chunk: range_bytes(url, *chunk), chunks))
        if len({part[1] for part in parts}) != 1:
            raise ValueError("Repository size changed during acquisition")
        return b"".join(part[0] for part in parts), parts[0][1]
    response = get(url, headers={"Range": f"bytes={start}-{start + length - 1}"}, stream=True, bounded_range=True)
    if response.status_code != 206:
        response.close()
        raise ValueError("Repository did not honor bounded Range request")
    match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
    if (not match or int(match[1]) != start or int(match[3]) <= start
            or int(match[2]) != min(start + length - 1, int(match[3]) - 1)):
        response.close()
        raise ValueError("Invalid Content-Range")
    try:
        data = bytearray()
        for chunk in response.iter_content(65536):
            if len(data) + len(chunk) > length:
                raise ValueError("Range response exceeded requested byte budget")
            data.extend(chunk)
        data = bytes(data)
    finally:
        response.close()
    if len(data) != int(match[2]) - start + 1:
        raise ValueError("Incomplete range response")
    return data, int(match[3])


def aligned_records(data, endian, minimum_time=1e9):
    """Locate a record boundary by validating three consecutive record headers."""
    for offset in range(min(len(data), 65536)):
        cursor, records = offset, []
        while cursor + 16 <= len(data):
            sec, sub, size, original = struct.unpack_from(endian + "IIII", data, cursor)
            if not (minimum_time <= sec < 2e9 and sub < 1000000 and 14 <= size <= 262144 and size <= original):
                break
            if cursor + 16 + size > len(data):
                break
            records.append((sec + sub / 1e6, cursor, 16 + size))
            cursor += 16 + size
        if len(records) >= 3:
            return records
    raise ValueError("No verified PCAP record boundary in range")


def capture_subset(url, destination, mib=32, target_time=None):
    header, total = range_bytes(url, 0, 24)
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        return capture_ng_subset(url, destination, mib, target_time, total)
    endian = "<" if header[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    if header[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        raise ValueError("Only classic microsecond PCAP supports remote slicing")
    start = 24
    if target_time is not None:
        low, high = 24, max(24, total - 131072)
        for _ in range(22):
            middle = (low + high) // 2
            probe, _ = range_bytes(url, middle, min(131072, total - middle))
            records = aligned_records(probe, endian)
            if records[0][0] < target_time:
                low = middle
            else:
                high = middle
            if high - low < 131072:
                break
        start = low
    payload, _ = range_bytes(url, start, min(mib * 1024 ** 2, total - start))
    records = aligned_records(payload, endian)
    selected = [r for r in records if target_time is None or r[0] >= target_time]
    if not selected:
        raise ValueError("Target time absent from acquired range")
    begin, end = selected[0][1], selected[-1][1] + selected[-1][2]
    destination.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(destination, header + payload[begin:end])
    return {"url": url, "remote_bytes": total, "range_start": start + begin,
            "range_end": start + end - 1, "size": destination.stat().st_size,
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "first_timestamp": selected[0][0], "last_timestamp": selected[-1][0], "packets": len(selected)}


def capture_ng_subset(url, destination, mib, target_time, total):
    prefix, _ = range_bytes(url, 0, 65536)
    endian = "<" if prefix[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    cursor, metadata, resolution = 0, bytearray(), 1e-6
    while cursor + 12 <= len(prefix):
        kind, length = struct.unpack_from(endian + "II", prefix, cursor)
        if kind == 6:
            break
        if length < 12 or cursor + length > len(prefix):
            raise ValueError("Unsupported remote PCAPNG metadata")
        metadata.extend(prefix[cursor:cursor + length])
        if kind == 1:
            option = cursor + 16
            while option + 4 < cursor + length - 4:
                code, size = struct.unpack_from(endian + "HH", prefix, option)
                if code == 9 and size == 1:
                    value = prefix[option + 4]
                    resolution = (2 if value & 128 else 10) ** -(value & 127)
                option += 4 + (size + 3) // 4 * 4
        cursor += length
    def align(data):
        marker = struct.pack(endian + "I", 6)
        offset = data.find(marker)
        while offset >= 0:
            try:
                kind, length, interface, high, low, captured, original = struct.unpack_from(endian + "IIIIIII", data, offset)
                stamp = ((high << 32) | low) * resolution
                if 32 <= length <= 262144 and length % 4 == 0 and offset + length <= len(data) and interface == 0 and captured <= original and captured <= length - 32 and 1e9 <= stamp < 2e9 and struct.unpack_from(endian + "I", data, offset + length - 4)[0] == length:
                    return offset, stamp
            except struct.error:
                pass
            offset = data.find(marker, offset + 1)
        raise ValueError("No validated PCAPNG packet in range")
    start = cursor
    if target_time is not None:
        low, high = cursor, total - 262144
        for _ in range(22):
            middle = (low + high) // 2
            probe, _ = range_bytes(url, middle, 262144)
            _, stamp = align(probe)
            if stamp < target_time:
                low = middle
            else:
                high = middle
            if high - low < 262144:
                break
        start = low
    payload, _ = range_bytes(url, start, min(mib * 1024 ** 2, total - start))
    begin, _ = align(payload)
    cursor, kept, timestamps = begin, bytearray(metadata), []
    while cursor + 12 <= len(payload):
        kind, length = struct.unpack_from(endian + "II", payload, cursor)
        if length < 12 or length % 4 or cursor + length > len(payload):
            break
        if struct.unpack_from(endian + "I", payload, cursor + length - 4)[0] != length:
            raise ValueError("Invalid remote PCAPNG block trailer")
        if kind == 6:
            _, high, low = struct.unpack_from(endian + "III", payload, cursor + 8)
            stamp = ((high << 32) | low) * resolution
            if target_time is None or stamp >= target_time:
                kept.extend(payload[cursor:cursor + length])
                timestamps.append(stamp)
        elif kind in (0x0a0d0d0a, 1):
            raise ValueError("Remote range crosses section/interface boundaries")
        cursor += length
    if not timestamps:
        raise ValueError("Target time not found in PCAPNG range")
    destination.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(destination, kept)
    return dict(url=url, format="pcapng", remote_bytes=total, range_start=start + begin, range_end=start + cursor - 1,
                size=len(kept), sha256=hashlib.sha256(kept).hexdigest(), first_timestamp=timestamps[0], last_timestamp=timestamps[-1], packets=len(timestamps))


def ctu_labels(base, capture, dest):
    listing = get(base + "detailed-bidirectional-flow-labels/").text
    filename = re.search(r'href="([^"/]+\.binetflow)"', listing).group(1)
    first = capture["first_timestamp"] - 86400
    last = capture["last_timestamp"]
    count = 0
    url = base + "detailed-bidirectional-flow-labels/" + filename
    scanned = 0
    header, total = range_bytes(url, 0, 4096)
    columns = header.decode("utf-8").splitlines()[0].split(",")
    def row_time(line):
        value = line.split(",", 1)[0]
        return datetime.strptime(value, "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=ZoneInfo("Europe/Prague")).timestamp()
    def locate(timestamp):
        low, high = 0, max(0, total - 8192)
        while high - low > 8192:
            middle = (low + high) // 2
            probe, _ = range_bytes(url, middle, min(8192, total - middle))
            lines = probe.decode("utf-8").splitlines()
            stamp = row_time(lines[1])
            if stamp < timestamp:
                low = middle
            else:
                high = middle
        return low
    lower = locate(capture["first_timestamp"] - 3600)
    upper = min(total, locate(capture["last_timestamp"] + 2) + 16384)
    upper = max(upper, min(total, lower + 1024 ** 2))
    existing_rows = []
    previous_sha = None
    if dest.exists() and dest.stat().st_size:
        previous_sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        with dest.open(newline="", encoding="utf-8") as existing:
            existing_rows = list(csv.DictReader(existing))
    ranges, seen = [], set()
    def sampled_rows():
        # Sample across the whole file, preserving only complete CSV records.
        # Unlike an initial prefix this reaches bot flows after capture setup.
        size = min(1024 ** 2, upper - lower)
        offsets = sorted(set(lower + int((upper - lower - size) * index / 11) for index in range(12)))
        with ThreadPoolExecutor(max_workers=4) as pool:
            payloads = list(pool.map(lambda offset: range_bytes(url, offset, size)[0], offsets))
        for offset, payload in zip(offsets, payloads):
            ranges.append(dict(start=offset, end=offset + len(payload)-1, sha256=hashlib.sha256(payload).hexdigest()))
            lines = payload.decode("utf-8").splitlines()[1:-1]
            for row in csv.DictReader(lines, fieldnames=columns):
                identity = tuple(row.get(key, "") for key in columns)
                if identity not in seen:
                    seen.add(identity)
                    yield row
    temporary = dest.with_suffix(".csv.part")
    with temporary.open("w", newline="", encoding="utf-8") as output:
        reader = sampled_rows()
        writer = csv.DictWriter(output, fieldnames=["start", "end", "source", "destination", "sport", "dport", "protocol", "label"])
        writer.writeheader()
        for existing in existing_rows:
            writer.writerow(existing)
            count += 1
        for row in reader:
            scanned += 1
            label = row.get("Label", "")
            if "From-Botnet" in label:
                label = "botnet"
            elif "From-Normal" in label:
                label = "benign"
            else:
                continue
            try:
                stamp = datetime.strptime(row["StartTime"], "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=ZoneInfo("Europe/Prague")).timestamp()
                duration = float(row["Dur"])
                if stamp > last or stamp + duration < capture["first_timestamp"] or stamp < first:
                    continue
                def port(value):
                    return int(value, 16) if value.startswith("0x") else int(value or 0)
                writer.writerow(dict(start=stamp, end=stamp + duration, source=row["SrcAddr"], destination=row["DstAddr"],
                                     sport=port(row["Sport"]), dport=port(row["Dport"]),
                                     protocol={"tcp": 6, "udp": 17, "icmp": 1}.get(row["Proto"], 0), label=label))
                count += 1
            except (ValueError, KeyError):
                continue
    temporary.replace(dest)
    return {"url": url, "matched_flows": count, "timezone": "Europe/Prague", "scanned_rows": scanned,
            "coverage": "Up to 12 distributed 1MiB capture-window ranges; unmatched flows excluded", "ranges": ranges,
            "previous_labels_sha256": previous_sha, "retained_previous_rows": len(existing_rows),
            "sha256": hashlib.sha256(dest.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mib", type=int, default=32)
    source_names = ["ctu1", "ctu2", "ctu9", "ctu10", "tuesday", "friday", "wednesday", "ctu-normal", "normal-dns", "mawi", "cse"]
    parser.add_argument("--sources", nargs="+", choices=source_names, default=source_names)
    parser.add_argument("--skip-labels", action="store_true")
    parser.add_argument("--refresh-labels", action="store_true")
    args = parser.parse_args()
    out = ROOT / "data/external"
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / "acquisition.json"
    manifest = load_manifest(manifest_path)
    errors = 0
    for key, value in manifest.items():
        if key in ("wednesday", "ctu1", "ctu2"):
            value["split"] = "train"
        elif key in ("ctu9", "ctu-normal"):
            value["split"] = "validation"
    for name in args.sources:
        try:
            folder = out / name
            folder.mkdir(exist_ok=True)
            previous_source = manifest.get(name, {})
            existing_capture = folder / "capture.pcap"
            if name in ("cse", "mawi", "normal-dns", "ctu-normal") and previous_source.get("status") in (
                    "schedule_labeled_subset", "unlabeled_ood_only", "verified_normal_dns", "verified_normal_capture"):
                if existing_capture.exists() and previous_source.get("capture", {}).get("sha256") == hashlib.sha256(existing_capture.read_bytes()).hexdigest():
                    print(name, "verified existing capture", flush=True)
                    continue
            if name == "cse":
                bucket = "https://cse-cic-ids2018.s3.amazonaws.com/"
                response = get(bucket, params={"list-type": "2", "prefix": "Original Network Traffic and Log data/Tuesday-20-02-2018/"})
                root = ET.fromstring(response.text)
                ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
                objects = [{"key": entry.findtext("s3:Key", namespaces=ns), "size": int(entry.findtext("s3:Size", namespaces=ns))} for entry in root.findall("s3:Contents", ns)]
                for entry in objects:
                    entry["url"] = bucket + quote(entry["key"])
                (folder / "archive_inventory.json").write_text(json.dumps(objects, indent=2))
                manifest[name] = dict(status="pending_archive_extraction", objects=objects, source_id="cse2018-tuesday", split="validation",
                                      reason="LOIC-UDP raw traffic is packaged in a 44 GB RAR archive; bounded PCAP range extraction is unavailable")
            elif name == "mawi":
                url = "https://mawi.wide.ad.jp/mawi/samplepoint-F/2024/202401011400.pcap.gz"
                capture_path = folder / "capture.pcap"
                count, timestamps = 0, []
                with get(url, stream=True) as response, gzip.GzipFile(fileobj=response.raw) as source, capture_path.with_suffix(".part").open("wb") as output:
                    output.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 262144, 1))
                    for stamp, raw, linktype in read_capture(source, max_packets=500000):
                        if linktype != 1:
                            raise ValueError("MAWI source requires explicit link-type conversion")
                        if output.tell() + len(raw) + 16 > args.mib * 1024 ** 2:
                            break
                        output.write(struct.pack("<IIII", int(stamp), int((stamp % 1) * 1e6), len(raw), len(raw)) + raw)
                        timestamps.append(stamp)
                        count += 1
                capture_path.with_suffix(".part").replace(capture_path)
                manifest[name] = dict(status="unlabeled_ood_only", source_id="mawi-20240101", split="ood",
                                      capture=dict(url=url, packets=count, size=capture_path.stat().st_size, sha256=hashlib.sha256(capture_path.read_bytes()).hexdigest()),
                                      reason="No benign assumption: annotations and independent label audit required")
            elif name == "normal-dns":
                url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/2015-03-24_capture1-only-dns.pcap"
                payload = get(url).content
                (folder / "capture.pcap").write_bytes(payload)
                manifest[name] = dict(status="verified_normal_dns", source_id="ctu-normal4-2015", split="train",
                                      capture=dict(url=url, size=len(payload), sha256=hashlib.sha256(payload).hexdigest()),
                                      label_policy="Only published normal host 10.0.0.34 communicating UDP/53 with 8.8.8.8 or 8.8.4.4")
            elif name == "ctu-normal":
                url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/normal-capture-20110817.pcap"
                payload = get(url).content
                (folder / "capture.pcap").write_bytes(payload)
                manifest[name] = dict(status="verified_normal_capture", source_id="ctu9", split="validation", capture={"url": url, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)})
            elif name.startswith("ctu"):
                previous = manifest.get(name, {})
                target_time = datetime.fromisoformat("2011-08-18T11:20:00+02:00").timestamp() if name == "ctu10" else None
                labels_path = folder / "labels.csv"
                capture_matches = existing_capture.exists() and previous.get("capture", {}).get("sha256") == hashlib.sha256(existing_capture.read_bytes()).hexdigest()
                if not args.refresh_labels and capture_matches and previous.get("status") == "labeled" and previous.get("capture", {}).get("requested_time") == target_time and labels_path.exists() and previous.get("labels", {}).get("sha256") == hashlib.sha256(labels_path.read_bytes()).hexdigest():
                    print(name, "verified existing capture and labels", flush=True)
                    continue
                number = {"ctu1": 42, "ctu2": 43, "ctu9": 50, "ctu10": 51}[name]
                base = f"https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-{number}/"
                listing = get(base).text
                filename = re.search(r'href="(botnet-capture-[^"/]+\.pcap)"', listing).group(1)
                existing = manifest.get(name, {})
                if capture_matches and existing.get("capture", {}).get("requested_time") == target_time:
                    capture = existing.get("capture")
                else:
                    capture = capture_subset(base + filename, folder / "capture.pcap", args.mib, target_time)
                capture["requested_time"] = target_time
                manifest[name] = dict(status="capture_acquired", capture=capture, source_id=name, split={"ctu1": "train", "ctu2": "train", "ctu9": "validation", "ctu10": "test"}[name])
                save_source(manifest_path, name, manifest[name])
                print(name, "capture acquired", capture["packets"], flush=True)
                if not args.skip_labels:
                    manifest[name]["labels"] = ctu_labels(base, capture, folder / "labels.csv")
                    manifest[name]["status"] = "labeled"
            else:
                day, time = {"tuesday": ("Tuesday-WorkingHours", "2017-07-04T08:45:00-03:00"),
                             "friday": ("Friday-WorkingHours", "2017-07-07T15:56:00-03:00"),
                             "wednesday": ("Wednesday-workingHours", "2017-07-05T10:43:00-03:00")}[name]
                target = datetime.fromisoformat(time).timestamp()
                url = f"https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap/{day}.pcap"
                previous = manifest.get(name, {}).get("capture", {})
                capture_path = folder / "capture.pcap"
                if (capture_path.exists() and previous.get("url") == url and previous.get("sha256") == hashlib.sha256(capture_path.read_bytes()).hexdigest()
                        and previous.get("first_timestamp", 0) >= target and previous.get("first_timestamp", 0) < target + 1800):
                    capture = previous
                else:
                    capture = capture_subset(url, capture_path, args.mib, target)
                # Acquisition time is not a ground-truth label. Dataset building
                # requires externally verified per-flow labels for these captures.
                manifest[name] = dict(status="requires_flow_labels", source_id=name, capture=capture, split="train" if name == "wednesday" else "test")
            print(name, manifest[name]["status"], flush=True)
        except Exception as error:
            errors += 1
            manifest.setdefault(name, {})["error"] = str(error)
            print(name, "ERROR", error, flush=True)
        save_source(manifest_path, name, manifest[name])
    if errors:
        raise SystemExit(f"{errors} source acquisition(s) failed; inspect acquisition.json")


if __name__ == "__main__":
    main()
