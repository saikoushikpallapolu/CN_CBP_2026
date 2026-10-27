"""Verify exact representation invariance on real captures after identity changes."""
import argparse
import hashlib
import json
import random
from pathlib import Path
from data_processing.production import REPRESENTATION, parse_packet, packet_features, read_capture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("captures", nargs="+")
    parser.add_argument("--packets", type=int, default=2000)
    parser.add_argument("--output", default="artifacts/identity_audit.json")
    args = parser.parse_args()
    rng = random.Random(42)
    checked = failures = 0
    sources = []
    for capture in args.captures:
        sources.append({"filename": Path(capture).name, "sha256": hashlib.sha256(Path(capture).read_bytes()).hexdigest()})
        for stamp, raw, link in read_capture(capture, max_packets=args.packets, allow_truncated="slice100MB" in capture):
            packet = parse_packet(raw, stamp, link)
            if packet is None:
                continue
            mutated = bytearray(raw)
            if packet.network_offset == 16:
                mutated[6:14] = rng.randbytes(8)
            elif packet.network_offset == 20:
                mutated[12:20] = rng.randbytes(8)
            elif packet.network_offset:
                mutated[:12] = rng.randbytes(12)
            n, t = packet.network_offset, packet.transport_offset
            begin, length = (n + 12, 8) if packet.version == 4 else (n + 8, 32)
            mutated[begin:begin + length] = rng.randbytes(length)
            if packet.version == 4:
                mutated[n + 10:n + 12] = rng.randbytes(2)
            if packet.protocol in (6, 17):
                for offset in (t, t + 2):
                    if int.from_bytes(raw[offset:offset + 2], "big") > 1024:
                        mutated[offset:offset + 2] = rng.randint(1025, 65535).to_bytes(2, "big")
                checksum = t + (16 if packet.protocol == 6 else 6)
                mutated[checksum:checksum + 2] = rng.randbytes(2)
            transformed = parse_packet(bytes(mutated), stamp, link)
            failures += packet_features(packet) != packet_features(transformed)
            checked += 1
    report = dict(representation=REPRESENTATION, checked=checked, failures=failures, exact_tensor_invariance=checked > 0 and failures == 0, sources=sources)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
