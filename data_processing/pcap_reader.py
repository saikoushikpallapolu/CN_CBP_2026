"""
Phase 1C — Read PCAP / PCAPNG files and extract raw frame bytes.

Unit II link: each captured frame is a sequence of bytes (headers + payload).
We flatten those into one continuous byte stream for later image conversion.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scapy.utils import PcapReader


def extract_bytes_from_pcap(
    pcap_path: str | Path,
    max_packets: int | None = None,
    max_bytes: int | None = None,
) -> bytes:
    """
    Open one PCAP/PCAPNG file and collect raw frame bytes into one bytes object.

    Prefer each packet's original on-wire bytes when available (true capture
    framing). Falls back to Scapy's serialized form otherwise.

    Optional limits are useful for smoke tests on large files.
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP not found: {path}")

    chunks: list[bytes] = []
    total = 0
    packet_count = 0

    # PcapReader streams packets (better for large files than rdpcap).
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if getattr(pkt, "original", None):
                frame = bytes(pkt.original)
            else:
                frame = bytes(pkt)

            chunks.append(frame)
            total += len(frame)
            packet_count += 1

            if max_packets is not None and packet_count >= max_packets:
                break
            if max_bytes is not None and total >= max_bytes:
                break

    return b"".join(chunks)


def summarize_pcap(
    pcap_path: str | Path,
    max_packets: int | None = None,
    max_bytes: int | None = None,
) -> dict:
    """Extract bytes and return a small summary dict (for CLI / tests)."""
    data = extract_bytes_from_pcap(
        pcap_path, max_packets=max_packets, max_bytes=max_bytes
    )
    path = Path(pcap_path)
    return {
        "path": str(path.resolve()),
        "file_size_bytes": path.stat().st_size,
        "extracted_bytes": len(data),
        "first_16_bytes_hex": data[:16].hex() if data else "",
        "max_packets": max_packets,
        "max_bytes": max_bytes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read a PCAP/PCAPNG and print how many frame bytes were extracted."
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default="data/raw/benign/Monday-WorkingHours_slice100MB.pcap",
        help="Path to a .pcap / .pcapng file",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Stop after this many packets (optional smoke-test limit)",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Stop after collecting about this many bytes (optional)",
    )
    args = parser.parse_args(argv)

    try:
        summary = summarize_pcap(
            args.pcap,
            max_packets=args.max_packets,
            max_bytes=args.max_bytes,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — show friendly CLI error
        print(f"ERROR while reading PCAP: {exc}", file=sys.stderr)
        return 1

    print("PCAP reader - Phase 1C")
    print(f"  file:            {summary['path']}")
    print(f"  file size:       {summary['file_size_bytes']:,} bytes")
    print(f"  extracted bytes: {summary['extracted_bytes']:,}")
    print(f"  first 16 (hex):  {summary['first_16_bytes_hex']}")
    if summary["max_packets"] is not None:
        print(f"  max_packets:     {summary['max_packets']}")
    if summary["max_bytes"] is not None:
        print(f"  max_bytes:       {summary['max_bytes']}")
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
