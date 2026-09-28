import os
import sys
import random
from pathlib import Path
import argparse

# Allow imports from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data_processing.image_transform import BYTES_PER_IMAGE, bytes_to_png
from scapy.utils import PcapReader

LABELS = ("benign", "ddos", "botnet")

def iter_frame_bytes_safe(pcap_path: Path):
    try:
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                if getattr(pkt, "original", None):
                    yield bytes(pkt.original)
                else:
                    yield bytes(pkt)
    except Exception as e:
        print(f"    [!] Malformed tail encountered in {pcap_path.name}: {e}")

def convert_pcap_stratified(
    pcap_path: Path,
    output_dir: Path,
    label: str,
    target_images: int,
) -> dict:
    
    # Pass 1: Count total valid bytes
    print(f"  [Pass 1] Estimating valid bytes for {pcap_path.name}...")
    total_valid_bytes = 0
    for frame in iter_frame_bytes_safe(pcap_path):
        total_valid_bytes += len(frame)
        
    total_windows = total_valid_bytes // BYTES_PER_IMAGE
    print(f"    Total valid bytes: {total_valid_bytes} ({total_windows} windows)")
    
    indices_to_keep = set()
    if total_windows <= target_images:
        print(f"    Warning: Total windows ({total_windows}) <= target ({target_images}). Will use all windows.")
        indices_to_keep = set(range(total_windows))
    else:
        # Stratified sampling
        # Divide the total_windows into `target_images` equal-sized bins
        # From each bin, pick a random window index
        random.seed(42)  # Deterministic sampling
        step = total_windows / target_images
        
        for i in range(target_images):
            start_idx = int(i * step)
            end_idx = int((i + 1) * step)
            
            # if end_idx exceeds total_windows (shouldn't happen with math, but safe to bound)
            end_idx = min(end_idx, total_windows)
            
            # Select random window in this bin
            if start_idx < end_idx:
                selected_idx = random.randint(start_idx, end_idx - 1)
            else:
                selected_idx = start_idx
                
            indices_to_keep.add(selected_idx)
            
        # Ensure exactly `target_images` (handle any potential edge case duplicates)
        while len(indices_to_keep) < target_images:
            missing = target_images - len(indices_to_keep)
            available = list(set(range(total_windows)) - indices_to_keep)
            random.shuffle(available)
            indices_to_keep.update(available[:missing])
            
    print(f"  [Pass 2] Extracting {len(indices_to_keep)} stratified windows...")
    output_dir.mkdir(parents=True, exist_ok=True)
    buffer = bytearray()
    written = 0
    window_idx = 0
    
    for frame in iter_frame_bytes_safe(pcap_path):
        buffer.extend(frame)
        while len(buffer) >= BYTES_PER_IMAGE:
            if window_idx in indices_to_keep:
                window = bytes(buffer[:BYTES_PER_IMAGE])
                out_path = output_dir / f"{label}_{written+1:04d}.png"
                bytes_to_png(window, out_path)
                written += 1
            del buffer[:BYTES_PER_IMAGE]
            window_idx += 1
            if written >= target_images:
                break
        if written >= target_images:
            break
            
    return {
        "valid_bytes": total_valid_bytes,
        "total_possible_windows": total_windows,
        "written": written
    }

def main():
    raw_root = Path("data/raw")
    processed_stratified = Path("data/processed_stratified")
    
    for label in LABELS:
        raw_dir = raw_root / label
        if not raw_dir.is_dir():
            continue
        pcaps = list(raw_dir.glob("*.pcap*"))
        if not pcaps:
            continue
        
        pcap_path = pcaps[0]
        out_dir = processed_stratified / label
        out_dir.mkdir(parents=True, exist_ok=True)
        
        # clear existing
        for p in out_dir.glob("*.png"):
            p.unlink()
            
        print(f"Processing {label}: {pcap_path.name}")
        stats = convert_pcap_stratified(pcap_path, out_dir, label, 2000)
        print(f"  -> Wrote {stats['written']} images for {label}\n")

if __name__ == '__main__':
    main()
