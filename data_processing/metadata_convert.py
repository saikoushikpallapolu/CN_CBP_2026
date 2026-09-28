import os
import sys
import json
from pathlib import Path
import numpy as np
from PIL import Image

# Allow imports from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scapy.utils import PcapReader

LABELS = ("benign", "botnet", "ddos")
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}

IMAGE_HEIGHT = 20
IMAGE_WIDTH = 20
PACKETS_PER_IMAGE = IMAGE_HEIGHT * IMAGE_WIDTH  # 400

def iter_packet_lengths_safe(pcap_path: Path):
    try:
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                if getattr(pkt, "original", None):
                    yield len(pkt.original)
                else:
                    yield len(pkt)
    except Exception as e:
        print(f"    [!] Malformed tail encountered in {pcap_path.name}: {e}")

def generate_metadata_images(
    pcap_path: Path,
    output_dir: Path,
    label: str,
    target_images: int,
) -> dict:
    
    output_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    all_lengths = []
    
    pixel_buffer = []
    
    for length in iter_packet_lengths_safe(pcap_path):
        all_lengths.append(length)
        
        # normalized length to [0, 255]
        pixel = int(min(length, 1500) / 1500.0 * 255)
        pixel_buffer.append(pixel)
        
        if len(pixel_buffer) == PACKETS_PER_IMAGE:
            arr = np.array(pixel_buffer, dtype=np.uint8).reshape((IMAGE_HEIGHT, IMAGE_WIDTH))
            image = Image.fromarray(arr, mode="L")
            out_path = output_dir / f"{label}_{written+1:04d}.png"
            image.save(out_path)
            
            written += 1
            pixel_buffer = []
            
            if written >= target_images:
                break
                
    # Save stats
    stats_path = output_dir / f"{label}_stats.json"
    with open(stats_path, 'w') as f:
        json.dump(all_lengths, f)
            
    return {
        "written": written,
        "lengths_processed": len(all_lengths)
    }

def main():
    raw_root = Path("data/raw")
    processed_dir = Path("data/processed_metadata")
    
    for label in LABELS:
        raw_dir = raw_root / label
        if not raw_dir.is_dir():
            continue
        pcaps = list(raw_dir.glob("*.pcap*"))
        if not pcaps:
            continue
        
        pcap_path = pcaps[0]
        out_dir = processed_dir / label
        out_dir.mkdir(parents=True, exist_ok=True)
        
        # clear existing images
        for p in out_dir.glob("*.png"):
            p.unlink()
            
        print(f"Processing {label}: {pcap_path.name}")
        stats = generate_metadata_images(pcap_path, out_dir, label, 2000)
        print(f"  -> Wrote {stats['written']} images for {label} (processed {stats['lengths_processed']} packets)\n")

if __name__ == '__main__':
    main()
