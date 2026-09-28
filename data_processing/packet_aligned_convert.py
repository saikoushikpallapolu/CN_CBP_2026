import os
import sys
import json
from pathlib import Path

# Allow imports from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data_processing.image_transform import pad_or_truncate, bytes_to_png, BYTES_PER_IMAGE
from scapy.utils import PcapReader

LABELS = ("benign", "botnet", "ddos")
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}

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

def convert_pcap_packet_aligned(
    pcap_path: Path,
    output_dir: Path,
    label: str,
    target_images: int,
) -> dict:
    
    output_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    packet_lengths = []
    
    for frame in iter_frame_bytes_safe(pcap_path):
        length = len(frame)
        packet_lengths.append(length)
        
        # pad_or_truncate already defined in image_transform handles < 4096 and > 4096
        window = pad_or_truncate(frame, BYTES_PER_IMAGE)
        out_path = output_dir / f"{label}_{written+1:04d}.png"
        bytes_to_png(window, out_path)
        written += 1
        
        if written >= target_images:
            break
            
    # Save stats
    stats_path = output_dir / f"{label}_stats.json"
    with open(stats_path, 'w') as f:
        json.dump(packet_lengths, f)
            
    return {
        "written": written,
        "lengths": packet_lengths
    }

def main():
    raw_root = Path("data/raw")
    processed_dir = Path("data/processed_packet_aligned")
    
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
        stats = convert_pcap_packet_aligned(pcap_path, out_dir, label, 2000)
        print(f"  -> Wrote {stats['written']} images for {label}\n")

if __name__ == '__main__':
    main()
