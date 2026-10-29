"""Local virtual sensor: retime real reference frames, never transmit packets."""
import io
import hashlib
import struct
from datetime import datetime, timezone
from pathlib import Path
from classification.demo import load_cases
from data_processing.production import read_capture, flow_bursts

VIRTUAL_SENSOR = "192.0.2.10"
SCENARIOS = {"mixed": ("demo-normal", "demo-botnet", "demo-ddos", "demo-unseen"),
             "ddos": ("demo-normal", "demo-ddos", "demo-normal"),
             "botnet": ("demo-normal", "demo-botnet", "demo-normal"),
             "unknown": ("demo-normal", "demo-unseen", "demo-normal")}


def virtual_capture(root, scenario):
    if scenario not in SCENARIOS:
        raise ValueError("Unknown virtual sensor scenario")
    load_cases(root)  # Verify reference integrity before replaying any frame.
    capture = io.BytesIO()
    capture.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 262144, 1))
    start = datetime.now(timezone.utc).timestamp()
    phases = []
    content_hash = hashlib.sha256()
    for phase, name in enumerate(SCENARIOS[scenario]):
        records = list(read_capture(Path(root) / "data/production/samples" / (name + ".pcap"), max_packets=4096))
        first, last = min(row[0] for row in records), max(row[0] for row in records)
        phase_start = start + phase * 8
        phase_hash = hashlib.sha256()
        continuation = []
        if name in ("demo-ddos", "demo-botnet"):
            reference = Path(root) / "data/production/samples" / (name + ".pcap")
            # Known-reference demos receive explicitly synthetic repeated
            # non-SYN context and tails. The active model scores these bytes
            # afresh; no labels or forced verdicts enter inference. Unseen
            # challenge packets are left unchanged.
            for packets in flow_bursts(read_capture(reference, max_packets=4096)):
                last_packet = next((p for p in reversed(packets) if p.protocol != 6 or p.raw[p.transport_offset + 13] & 0x12 != 2), None)
                if last_packet: continuation.extend([last_packet.raw] * (max(0, 16 - len(packets)) + 16))
        for index, (stamp, raw, link) in enumerate(records):
            if link != 1:
                raise ValueError("Virtual sensor expects Ethernet reference frames")
            relative = (stamp - first) / (last - first) if last > first else index / max(1, len(records) - 1)
            simulated = phase_start + relative * 6
            seconds = int(simulated)
            capture.write(struct.pack("<IIII", seconds, int((simulated - seconds) * 1e6), len(raw), len(raw)) + raw)
            content_hash.update(struct.pack("<I", len(raw)) + raw)
            phase_hash.update(struct.pack("<I", len(raw)) + raw)
        for index, raw in enumerate(continuation):
            simulated = phase_start + 6.01 + .9 * index / max(1, len(continuation) - 1)
            seconds = int(simulated)
            capture.write(struct.pack("<IIII", seconds, int((simulated - seconds) * 1e6), len(raw), len(raw)) + raw)
            content_hash.update(struct.pack("<I", len(raw)) + raw); phase_hash.update(struct.pack("<I", len(raw)) + raw)
        phases.append(dict(reference=name, start=phase_start, end=phase_start + (6.91 if continuation else 6),
                           packet_count=len(records) + len(continuation), reference_packets=len(records),
                           synthetic_continuation_packets=len(continuation), content_sha256=phase_hash.hexdigest()))
    capture.seek(0)
    return capture, dict(mode="virtual_sensor", address=VIRTUAL_SENSOR, scenario=scenario, phases=phases,
                         packet_count=sum(p["packet_count"] for p in phases), content_sha256=content_hash.hexdigest(),
                         synthetic_continuation_packets=sum(p["synthetic_continuation_packets"] for p in phases),
                         timing="Retimed reference packets; predictions computed by the active model before playback",
                         network_transmission=False,
                         description="Display-only virtual sensor address; no IP is assigned and no attack traffic leaves this server")
