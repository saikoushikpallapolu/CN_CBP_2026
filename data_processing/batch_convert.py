"""
Phase 1E — Batch convert every PCAP under data/raw/<label>/ into 64x64 PNGs.

Streams packets so we do not need the whole 100 MB file in memory at once.
Each non-overlapping 4096-byte window becomes one grayscale image.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scapy.utils import PcapReader

# Allow `python data_processing/batch_convert.py` from repo root.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data_processing.image_transform import (  # noqa: E402
    BYTES_PER_IMAGE,
    bytes_to_png,
)

LABELS = ("benign", "ddos", "botnet")
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}


def iter_frame_bytes(pcap_path: Path):
    """Yield original frame bytes from a PCAP/PCAPNG, one frame at a time."""
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if getattr(pkt, "original", None):
                yield bytes(pkt.original)
            else:
                yield bytes(pkt)


def convert_pcap_to_images(
    pcap_path: Path,
    output_dir: Path,
    label: str,
    max_images: int,
    start_index: int = 1,
) -> int:
    """
    Convert one PCAP into up to `max_images` PNGs under output_dir.
    Returns how many images were written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    buffer = bytearray()
    written = 0
    index = start_index

    for frame in iter_frame_bytes(pcap_path):
        buffer.extend(frame)
        while len(buffer) >= BYTES_PER_IMAGE and written < max_images:
            window = bytes(buffer[:BYTES_PER_IMAGE])
            del buffer[:BYTES_PER_IMAGE]
            out_path = output_dir / f"{label}_{index:04d}.png"
            bytes_to_png(window, out_path)
            written += 1
            index += 1
        if written >= max_images:
            break

    # If we still need images and have a partial window, pad one last image.
    if written < max_images and buffer:
        out_path = output_dir / f"{label}_{index:04d}.png"
        bytes_to_png(bytes(buffer), out_path)
        written += 1

    return written


def convert_label(
    raw_root: Path,
    processed_root: Path,
    label: str,
    max_images: int,
) -> int:
    raw_dir = raw_root / label
    out_dir = processed_root / label
    if not raw_dir.is_dir():
        print(f"  skip {label}: missing {raw_dir}")
        return 0

    pcaps = sorted(
        p
        for p in raw_dir.iterdir()
        if p.is_file() and p.suffix.lower() in PCAP_SUFFIXES
    )
    if not pcaps:
        print(f"  skip {label}: no PCAP files in {raw_dir}")
        return 0

    # Clear old generated PNGs for a clean batch (keep .gitkeep).
    for old in out_dir.glob("*.png"):
        old.unlink()

    total = 0
    remaining = max_images
    next_index = 1
    for pcap in pcaps:
        if remaining <= 0:
            break
        n = convert_pcap_to_images(
            pcap, out_dir, label, max_images=remaining, start_index=next_index
        )
        print(f"  {label}: {pcap.name} -> {n} images")
        total += n
        remaining -= n
        next_index += n
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Batch convert data/raw/<label>/*.pcap into 64x64 PNGs."
    )
    parser.add_argument(
        "--raw-root",
        type=Path,
        default=Path("data/raw"),
        help="Root folder with benign/ddos/botnet PCAPs",
    )
    parser.add_argument(
        "--processed-root",
        type=Path,
        default=Path("data/processed"),
        help="Root folder for output images",
    )
    parser.add_argument(
        "--max-images-per-class",
        type=int,
        default=2000,
        help="Cap images per label (enough for train/val/test without huge disk use)",
    )
    parser.add_argument(
        "--labels",
        nargs="+",
        default=list(LABELS),
        help="Which labels to convert",
    )
    args = parser.parse_args(argv)

    print("Batch convert - Phase 1E")
    print(f"  raw:       {args.raw_root.resolve()}")
    print(f"  processed: {args.processed_root.resolve()}")
    print(f"  max/class: {args.max_images_per_class}")

    counts: dict[str, int] = {}
    try:
        for label in args.labels:
            counts[label] = convert_label(
                args.raw_root,
                args.processed_root,
                label,
                args.max_images_per_class,
            )
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("Summary:")
    for label, n in counts.items():
        print(f"  {label}: {n}")
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
