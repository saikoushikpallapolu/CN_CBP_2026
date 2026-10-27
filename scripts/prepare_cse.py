"""Extract verified LOIC-UDP endpoint/time traffic from the acquired victim PCAP."""
import argparse
import hashlib
import json
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from data_processing.production import read_capture, parse_packet
from scripts.acquire_production_data import atomic_json, save_source

ATTACKERS = {"18.218.115.60", "18.219.9.1", "18.219.32.43", "18.218.55.126", "52.14.136.135",
             "18.219.5.43", "18.216.200.189", "18.218.229.235", "18.218.11.51", "18.216.24.42"}
VICTIMS = {"18.217.21.148", "172.31.69.25"}
SCHEDULES = {
    "cse": [("LOIC-HTTP", 6, "2018-02-20T10:12:00-04:00", "2018-02-20T11:17:00-04:00"),
            ("LOIC-UDP", 17, "2018-02-20T13:13:00-04:00", "2018-02-20T13:32:00-04:00")],
    "cse21": [("LOIC-UDP", 17, "2018-02-21T10:09:00-04:00", "2018-02-21T10:43:00-04:00"),
              ("HOIC", 6, "2018-02-21T14:05:00-04:00", "2018-02-21T15:05:00-04:00")],
}


def schedule_label(packet, report):
    endpoints = {packet.source, packet.destination}
    if not (endpoints & set(report["attackers"]) and endpoints & set(report["victims"])):
        return None
    for name, protocol, begin, end in report["windows"]:
        if packet.protocol == protocol and datetime.fromisoformat(begin).timestamp() <= packet.timestamp <= datetime.fromisoformat(end).timestamp():
            return "ddos"
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/external/cse/member.pcap")
    parser.add_argument("--mib", type=int, default=32)
    parser.add_argument("--source", choices=("cse", "cse21"), default="cse")
    parser.add_argument("--attacks", nargs="+", choices=("LOIC-HTTP", "LOIC-UDP", "HOIC"))
    parser.add_argument("--refresh-manifest-only", action="store_true")
    parser.add_argument("--allow-prefix", action="store_true", help="Use complete records from an interrupted decompressed prefix; records missing whole-member CRC explicitly")
    args = parser.parse_args()
    windows = SCHEDULES[args.source]
    if args.attacks:
        windows = [window for window in windows if window[0] in args.attacks]
        if not windows:
            parser.error("Requested attacks are not in this capture day's published schedule")
    numeric_windows = [(name, protocol, datetime.fromisoformat(begin).timestamp(), datetime.fromisoformat(end).timestamp()) for name, protocol, begin, end in windows]
    victims = VICTIMS if args.source == "cse" else {"18.218.83.150", "172.31.69.28"}
    source = Path(args.input)
    folder = source.parent
    if args.allow_prefix:
        inventory = json.loads((folder / "zip_members.json").read_text())
        member = next(row for row in inventory["members"] if "172.31.69.28 part 1" in row["filename"])
        atomic_json(folder / "prefix_acquisition.json", dict(url=inventory["url"], member=member,
                    available_prefix_bytes=source.stat().st_size, crc_verified=False,
                    limitation="Interrupted HTTPS decompression prefix; only complete PCAP records retained; whole-member CRC unavailable"))
    output = folder / "capture.pcap"
    if args.refresh_manifest_only:
        report = json.loads((folder / "window_audit.json").read_text())
        if not output.exists() or not report.get("accepted"):
            raise SystemExit("No previously verified prepared capture")
        timestamps = [stamp for stamp, raw, link in read_capture(output, max_packets=1000000)]
        record_manifest(folder, output, report, timestamps)
        return
    scanned, accepted, timestamps, observed_bins = 0, 0, [], Counter()
    budgets, accepted_by_attack = Counter(), Counter()
    link = None
    with output.with_suffix(".pcap.part").open("wb") as capture:
        for stamp, raw, linktype in read_capture(source, max_packets=100000000, allow_truncated=args.allow_prefix):
            scanned += 1
            active = next((name for name, protocol, begin, end in numeric_windows if begin <= stamp <= end and budgets[name] < args.mib * 1024 ** 2), None)
            if active is None:
                if all(budgets[name] >= args.mib * 1024 ** 2 for name, *_ in numeric_windows):
                    break
                continue
            packet = parse_packet(raw, stamp, linktype)
            if packet is None or not any(name == active and packet.protocol == protocol for name, protocol, *_ in numeric_windows):
                continue
            endpoints = {packet.source, packet.destination}
            if not (endpoints & ATTACKERS and endpoints & victims):
                continue
            observed_bins[int(stamp) // 3600 * 3600] += 1
            if link is None:
                link = linktype
                capture.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 262144, link))
            if link != linktype:
                raise ValueError("Mixed-link capture must retain PCAPNG interfaces")
            capture.write(struct.pack("<IIII", int(stamp), int((stamp % 1) * 1e6), len(raw), len(raw)) + raw)
            budgets[active] += len(raw) + 16
            accepted_by_attack[active] += 1
            accepted += 1
            timestamps.append(stamp)
    report = dict(scanned=scanned, accepted=accepted, source=args.source, windows=windows,
                  prefix_only=args.allow_prefix,
                  attackers=sorted(ATTACKERS), victims=sorted(victims), accepted_by_attack=dict(accepted_by_attack),
                  known_attacker_udp_bins={datetime.fromtimestamp(key, timezone.utc).isoformat(): value for key, value in observed_bins.items()},
                  label_basis="Published attacker/victim endpoints, protocol and attack schedule; independent flow-CSV audit pending")
    atomic_json(folder / "window_audit.json", report)
    if not accepted:
        raise SystemExit("No endpoint/time matches. Capture timestamps must be independently reconciled; no labels assigned.")
    output.with_suffix(".pcap.part").replace(output)
    record_manifest(folder, output, report, timestamps)
    print(json.dumps(report, indent=2))


def record_manifest(folder, output, report, timestamps):
    evidence = "prefix_acquisition.json" if report.get("prefix_only") else "extraction.json"
    extraction = json.loads((folder / evidence).read_text())
    name = report["source"]
    metadata = dict(status="schedule_labeled_subset", source_id="cse2018-" + name, split="train" if name == "cse" else "validation",
                           capture=dict(url=extraction["url"], archive_member=extraction["member"]["filename"], packets=len(timestamps),
                                        first_timestamp=timestamps[0], last_timestamp=timestamps[-1], size=output.stat().st_size,
                                        sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                                        whole_archive_member_crc_verified=extraction.get("crc_verified", not report.get("prefix_only"))), label_audit=report)
    save_source(Path("data/external/acquisition.json"), name, metadata)


if __name__ == "__main__":
    main()
