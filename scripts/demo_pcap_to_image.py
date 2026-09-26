"""
Demo: PCAP -> byte list in terminal -> 64x64 grayscale (+ large zoomed preview).

The real CNN image is only 64x64 (looks blocky on purpose).
This script also saves a ZOOMED copy (nearest-neighbor) so you can see the pattern.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data_processing.image_transform import (  # noqa: E402
    BYTES_PER_IMAGE,
    IMAGE_HEIGHT,
    IMAGE_WIDTH,
    bytes_to_array,
    bytes_to_png,
)
from data_processing.pcap_reader import extract_bytes_from_pcap  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Show PCAP bytes as a grayscale traffic image (real 64x64 + zoomed view)."
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default="data/raw/benign/Monday-WorkingHours_slice100MB.pcap",
        help="PCAP/PCAPNG file to convert (your upload / local path)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="data/processed/demo_preview.png",
        help="Where to save the REAL 64x64 PNG (used by the model later)",
    )
    parser.add_argument(
        "--zoom",
        type=int,
        default=512,
        help="Side length of the ZOOMED preview so humans can see it (default 512)",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Save only; do not open the image viewer",
    )
    parser.add_argument(
        "--preview-bytes",
        type=int,
        default=64,
        help="How many raw byte numbers to print in the terminal",
    )
    args = parser.parse_args(argv)

    pcap_path = Path(args.pcap)
    if not pcap_path.is_file():
        print(f"ERROR: file not found: {pcap_path}", file=sys.stderr)
        print("Tip: put a .pcap next to the project or use one of:", file=sys.stderr)
        print("  data/raw/benign/Monday-WorkingHours_slice100MB.pcap", file=sys.stderr)
        print("  data/raw/ddos/Wednesday-workingHours_slice100MB.pcap", file=sys.stderr)
        print("  data/raw/botnet/Friday-WorkingHours_slice100MB.pcap", file=sys.stderr)
        return 1

    try:
        raw = extract_bytes_from_pcap(pcap_path, max_bytes=BYTES_PER_IMAGE)
        arr = bytes_to_array(raw)
        out_real = bytes_to_png(raw, args.output)

        # Zoom with nearest-neighbor so each original pixel stays a sharp block.
        out_zoom = Path(args.output).with_name(
            Path(args.output).stem + f"_zoomed_{args.zoom}.png"
        )
        Image.fromarray(arr, mode="L").resize(
            (args.zoom, args.zoom), resample=Image.Resampling.NEAREST
        ).save(out_zoom)
        out_zoom = out_zoom.resolve()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    preview_n = min(args.preview_bytes, len(raw))
    preview = list(raw[:preview_n])

    print("=" * 60)
    print("WHAT HAPPENED (PCAP -> bytes -> grayscale image)")
    print("=" * 60)
    print()
    print("1) INPUT FILE (what you uploaded / pointed to)")
    print(f"   {pcap_path.resolve()}")
    print()
    print("2) BYTE LIST (first numbers from the traffic frames)")
    print(f"   Each number is 0-255. These become pixel brightness.")
    print(f"   Showing first {preview_n} of {BYTES_PER_IMAGE} used for the image:")
    print(f"   {preview}")
    print()
    print("3) REAL MODEL IMAGE (tiny on purpose - 64x64)")
    print(f"   shape: {IMAGE_HEIGHT}x{IMAGE_WIDTH}  mode: grayscale")
    print(f"   pixel min/max: {int(arr.min())} / {int(arr.max())}")
    print(f"   saved: {out_real}")
    print("   (This looks pixelated if you zoom - that is correct.)")
    print()
    print("4) ZOOMED PREVIEW (easy for humans to see)")
    print(f"   saved: {out_zoom}")
    print("   Open THIS file to see the traffic texture clearly.")
    print()

    if not args.no_open:
        try:
            os.startfile(str(out_zoom))  # type: ignore[attr-defined]
            print("Opened the ZOOMED preview in your default image viewer.")
        except Exception:
            Image.open(out_zoom).show()
            print("Opened the ZOOMED preview via PIL.")

    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
