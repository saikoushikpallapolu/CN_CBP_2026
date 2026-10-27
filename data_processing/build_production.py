"""Build flow tensors with provenance, packet-time labels and disjoint sources."""
import argparse
import csv
import hashlib
import json
import struct
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np

from data_processing.production import REPRESENTATION, burst_array, flow_bursts, read_capture

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ["benign", "botnet", "ddos"]


class FlowLabels:
    def __init__(self, path):
        self.index = defaultdict(list)
        self.clock_offset = 0.
        self.time_tolerance = .001
        self.clock_evidence = {"method": "unadjusted"}
        with open(path, newline="", encoding="utf-8") as file:
            for row in csv.DictReader(file):
                key = (int(row["protocol"]), *sorted(((row["source"], int(row["sport"])), (row["destination"], int(row["dport"])))))
                self.index[key].append((float(row["start"]), float(row["end"]), row["label"]))

    def __call__(self, packet):
        timestamp = packet.timestamp + self.clock_offset
        matches = {label for start, end, label in self.index.get(packet.key, []) if start - self.time_tolerance <= timestamp <= end + self.time_tolerance}
        return matches.pop() if len(matches) == 1 else None

    def align_capture_clock(self, capture):
        """Measure VM-vs-router capture clock skew from matching TCP SYN events.

        No accuracy optimization or test labels are used. A robust, bounded skew
        estimate is recorded and rejected if the event residuals are unstable.
        """
        from data_processing.production import parse_packet
        seen, differences = set(), []
        for timestamp, raw, linktype in read_capture(capture, max_packets=2000000):
            packet = parse_packet(raw, timestamp, linktype)
            if packet is None or packet.protocol != 6 or raw[packet.transport_offset + 13] & 0x12 != 2 or packet.key in seen:
                continue
            seen.add(packet.key)
            candidates = [start - timestamp for start, end, label in self.index.get(packet.key, []) if abs(start - timestamp) < 2]
            if candidates:
                differences.append(min(candidates, key=abs))
        if len(differences) >= 20:
            median = float(np.median(differences))
            residuals = np.abs(np.array(differences) - median)
            mad = float(np.median(residuals))
            if mad < .1:
                self.clock_offset = median
                self.time_tolerance = min(.1, max(.001, float(np.percentile(residuals, 95)) + .005))
                self.clock_evidence = dict(method="median matched SYN start delta", matched_events=len(differences),
                                           offset_seconds=median, median_absolute_residual_seconds=mad,
                                           join_tolerance_seconds=self.time_tolerance,
                                           limitation="independent flow-label audit remains required")


def cic_label(name, packet):
    """Conservative published attack-window AND endpoint labels, never filename labels.

    Windows use Atlantic daylight time. Wednesday DoS is folded into the ddos
    family explicitly; the report retains this taxonomy limitation.
    """
    if name == "monday":
        return "benign"
    if name == "tuesday":
        start = datetime.fromisoformat("2017-07-04T08:30:00-03:00").timestamp()
        end = datetime.fromisoformat("2017-07-04T09:15:00-03:00").timestamp()
        return "benign" if start <= packet.timestamp < end else None
    windows = {"wednesday": ("2017-07-05T10:43:00-03:00", "2017-07-05T11:00:00-03:00", "205.174.165.73"),
               "friday": ("2017-07-07T15:56:00-03:00", "2017-07-07T16:16:00-03:00", "172.16.0.1")}
    if name not in windows:
        return None
    start, end, attacker = windows[name]
    endpoints = {packet.source, packet.destination}
    attacker_visible = attacker in endpoints or (name == "wednesday" and "172.16.0.1" in endpoints)
    if (datetime.fromisoformat(start).timestamp() <= packet.timestamp <= datetime.fromisoformat(end).timestamp()
            and attacker_visible and "192.168.10.50" in endpoints):
        return "ddos"
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-per-source", type=int, default=20000)
    parser.add_argument("--output", default="data/production/dataset.npz")
    args = parser.parse_args()
    manifest_path = ROOT / "data/external/acquisition.json"
    from scripts.acquire_production_data import load_manifest
    acquired = load_manifest(manifest_path)
    sources = [("monday", ROOT / "data/raw/benign/Monday-WorkingHours_slice100MB.pcap", "train", lambda p: "benign")]
    for name, metadata in acquired.items():
        if metadata.get("status") in ("unlabeled_ood_only", "pending_archive_extraction"):
            continue
        path = ROOT / "data/external" / name / "capture.pcap"
        if not path.exists():
            continue
        if name in ("cse", "cse21"):
            split = metadata["split"]
            from scripts.prepare_cse import schedule_label
            audit = metadata["label_audit"]
            if "windows" not in audit:
                raise ValueError("Re-run prepare_cse to establish independent multi-attack sources")
            labeler = lambda p, audit=audit: schedule_label(p, audit)
        elif name == "normal-dns":
            split = "train"
            labeler = lambda p: "benign" if p.protocol == 17 and 53 in (p.sport, p.dport) and "10.0.0.34" in (p.source, p.destination) and ({p.source, p.destination} & {"8.8.8.8", "8.8.4.4"}) else None
        elif name == "ctu-normal":
            split, labeler = "validation", lambda p: "benign"
        elif name.startswith("ctu"):
            labels = path.with_name("labels.csv")
            if not labels.exists() or metadata.get("status") != "labeled":
                continue
            split = {"ctu1": "train", "ctu2": "train", "ctu9": "validation", "ctu10": "test"}[name]
            labeler = FlowLabels(labels)
            labeler.align_capture_clock(path)
        else:
            split = "train" if name == "wednesday" else "test"
            labeler = lambda p, name=name: cic_label(name, p)
        sources.append((name, path, split, labeler))
    sources.sort(key=lambda source: {"train": 0, "validation": 1, "test": 2}[source[2]])
    arrays, labels, groups, splits, packet_counts, hashes = [], [], [], [], [], set()
    representation_labels = defaultdict(set)
    report = {"representation": REPRESENTATION, "sources": {}, "discarded_duplicates": 0,
              "label_policy": "CTU bidirectional flow intervals; CIC conservative published window + endpoints; unknown excluded"}
    for name, path, split, labeler in sources:
        count, excluded = 0, 0
        counts = defaultdict(int)
        attack_counts = defaultdict(int)
        attack_windows = acquired.get(name, {}).get("label_audit", {}).get("windows", []) if name in ("cse", "cse21") else []
        per_attack_budget = max(1, args.max_per_source // len(attack_windows)) if attack_windows else None
        for packets in flow_bursts(read_capture(path, max_packets=2000000, allow_truncated="slice100MB" in path.name)):
            truth = {labeler(p) for p in packets}
            if len(truth) != 1 or None in truth:
                excluded += 1
                continue
            label = truth.pop()
            attack = None
            if attack_windows:
                first_packet = packets[0]
                attack = next((attack_name for attack_name, protocol, begin, end in attack_windows
                               if protocol == first_packet.protocol and datetime.fromisoformat(begin).timestamp() <= first_packet.timestamp <= datetime.fromisoformat(end).timestamp()), None)
                if attack is None or attack_counts[attack] >= per_attack_budget:
                    continue
            array = burst_array(packets)
            # Identical sanitized handshakes from different genuine sessions are
            # not leakage: retain them, including conflicting class semantics.
            # Deduplicate only exact raw packet events (timestamp + full frame).
            event = hashlib.sha256()
            for packet in packets:
                event.update(struct.pack("!dI", packet.timestamp, len(packet.raw)))
                event.update(packet.raw)
            digest = event.digest()
            if digest in hashes:
                report["discarded_duplicates"] += 1
                continue
            hashes.add(digest)
            representation_labels[hashlib.sha256(array.tobytes()).digest()].add(label)
            arrays.append(array)
            packet_counts.append(len(packets))
            labels.append(CLASSES.index(label))
            groups.append("ctu9" if name == "ctu-normal" else name)
            splits.append(split)
            counts[label] += 1
            if attack:
                attack_counts[attack] += 1
            count += 1
            if count >= args.max_per_source:
                break
        report["sources"][name] = dict(split=split, accepted=count, excluded=excluded, classes=dict(counts),
                                        sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        if attack_windows:
            report["sources"][name]["samples_by_attack"] = dict(attack_counts)
            report["sources"][name]["sampling_policy"] = f"At most {per_attack_budget} bursts per published attack window; scan past full earlier windows"
        if isinstance(labeler, FlowLabels):
            report["sources"][name]["clock_alignment"] = labeler.clock_evidence
        print(name, report["sources"][name], flush=True)
    if not arrays:
        raise SystemExit("No verified labeled flow bursts acquired")
    report["ambiguous_representation_count"] = sum(len(classes) > 1 for classes in representation_labels.values())
    report["deduplication_policy"] = "Exact raw packet events only; naturally identical sanitized fingerprints retained"
    destination = ROOT / args.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(destination, x=np.stack(arrays), y=np.array(labels), packets=np.array(packet_counts), source=np.array(groups), split=np.array(splits), representation=REPRESENTATION)
    destination.with_suffix(".json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
