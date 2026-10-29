"""Build small demos from independently labeled raw flows, never predictions."""
import hashlib
import json
import struct
from pathlib import Path
from data_processing.production import flow_bursts, read_capture, REPRESENTATION
from data_processing.build_production import FlowLabels
from scripts.prepare_cse import schedule_label


def main():
    output = Path("data/production/samples")
    output.mkdir(parents=True, exist_ok=True)
    folder = Path("data/external")
    labels = FlowLabels(folder / "ctu10/labels.csv")
    labels.align_capture_clock(folder / "ctu10/capture.pcap")
    hoic = json.loads((folder / "cse21-hoic/source.json").read_text())["label_audit"]
    loic = json.loads((folder / "cse/source.json").read_text())["label_audit"]
    cases = [
        ("demo-normal", "Normal traffic", "benign", "ctu9", folder / "ctu-normal/capture.pcap", lambda p: "benign", "Published controlled normal capture"),
        ("demo-botnet", "Botnet traffic", "botnet", "ctu10", folder / "ctu10/capture.pcap", labels, "Official bidirectional flow intervals and endpoints"),
        ("demo-ddos", "Known LOIC DDoS", "ddos", "cse2018-tuesday", folder / "cse/capture.pcap", lambda p: schedule_label(p, loic), "Published schedule and endpoints; training-source demonstration, not independent accuracy evidence"),
        ("demo-unseen", "Unseen HOIC attack", "ddos", "cse21", folder / "cse21-hoic/capture.pcap", lambda p: schedule_label(p, hoic), "Published HOIC schedule and endpoints; UNKNOWN is an escalation"),
    ]
    manifest = dict(representation=REPRESENTATION, selection="First 32 label-consistent bursts; no model scores or predictions used", cases=[])
    for case_id, title, expected, group, source, labeler, basis in cases:
        selected = []
        for packets in flow_bursts(read_capture(source, max_packets=2000000)):
            if {labeler(packet) for packet in packets} == {expected}:
                selected.append(packets)
                if len(selected) == 32:
                    break
        if not selected:
            raise ValueError("No verified demo bursts for " + case_id)
        target = output / (case_id + ".pcap")
        # Keep each selected complete burst. TCP SYN/session boundaries remain
        # intact; sort packet events into their original chronological order.
        records = sorted((p for burst in selected for p in burst), key=lambda p: p.timestamp)
        with target.open("wb") as capture:
            capture.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 262144, 1))
            for packet in records:
                capture.write(struct.pack("<IIII", int(packet.timestamp), int(packet.timestamp % 1 * 1e6), len(packet.raw), len(packet.raw)) + packet.raw)
        manifest["cases"].append(dict(id=case_id, title=title, expected_class=expected, source_group=group,
                                      label_basis=basis, packets=len(records), selected_bursts=len(selected),
                                      sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                                      source_sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
    (output / "demo-manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
