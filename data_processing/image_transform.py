"""
Phase 1D — Convert a byte stream into a fixed-size 2D grayscale image.

Design (docs/design.md):
  - Need exactly 4096 bytes → reshape to 64 x 64
  - Pad with 0 if shorter; truncate if longer
  - Each byte (0-255) = one pixel brightness
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
from PIL import Image

IMAGE_HEIGHT = 64
IMAGE_WIDTH = 64
BYTES_PER_IMAGE = IMAGE_HEIGHT * IMAGE_WIDTH  # 4096


def pad_or_truncate(data: bytes | bytearray | memoryview, length: int = BYTES_PER_IMAGE) -> bytes:
    """Keep the first `length` bytes; pad with zeros if shorter."""
    raw = bytes(data)
    if len(raw) >= length:
        return raw[:length]
    return raw + (b"\x00" * (length - len(raw)))


def bytes_to_array(data: bytes | bytearray | memoryview) -> np.ndarray:
    """
    Pad/truncate to 4096 bytes and reshape into a uint8 (64, 64) grid (row-major).
    """
    fixed = pad_or_truncate(data, BYTES_PER_IMAGE)
    arr = np.frombuffer(fixed, dtype=np.uint8)
    return arr.reshape((IMAGE_HEIGHT, IMAGE_WIDTH))


def save_grayscale_png(array_2d: np.ndarray, output_path: str | Path) -> Path:
    """Save a 2D uint8 array as a grayscale PNG."""
    if array_2d.shape != (IMAGE_HEIGHT, IMAGE_WIDTH):
        raise ValueError(
            f"Expected shape {(IMAGE_HEIGHT, IMAGE_WIDTH)}, got {array_2d.shape}"
        )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.fromarray(array_2d, mode="L")
    image.save(path)
    return path.resolve()


def bytes_to_png(data: bytes | bytearray | memoryview, output_path: str | Path) -> Path:
    """One-shot: bytes → 64x64 grayscale PNG."""
    return save_grayscale_png(bytes_to_array(data), output_path)


def main(argv: list[str] | None = None) -> int:
    """Demo: read bytes from a PCAP (via pcap_reader) and write one test PNG."""
    # Allow running as script without installing the package.
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from data_processing.pcap_reader import extract_bytes_from_pcap

    parser = argparse.ArgumentParser(
        description="Convert PCAP frame bytes into one 64x64 grayscale PNG."
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default="data/raw/benign/Monday-WorkingHours_slice100MB.pcap",
        help="Input PCAP/PCAPNG path",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="data/processed/benign/test_sample.png",
        help="Output PNG path",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=BYTES_PER_IMAGE,
        help="How many raw bytes to pull from the PCAP before imaging",
    )
    args = parser.parse_args(argv)

    try:
        raw = extract_bytes_from_pcap(args.pcap, max_bytes=args.max_bytes)
        out = bytes_to_png(raw, args.output)
        img = Image.open(out)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("Image transform - Phase 1D")
    print(f"  pcap:          {Path(args.pcap).resolve()}")
    print(f"  bytes used:    {min(len(raw), BYTES_PER_IMAGE)} (padded/truncated to {BYTES_PER_IMAGE})")
    print(f"  output:        {out}")
    print(f"  size:          {img.size[0]}x{img.size[1]}")
    print(f"  mode:          {img.mode}")
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
