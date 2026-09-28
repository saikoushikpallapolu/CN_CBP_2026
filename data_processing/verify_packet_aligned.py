import os
import json
from pathlib import Path
from PIL import Image
import hashlib

def main():
    print("Verification Report: Packet Aligned Dataset")
    print("=" * 60)
    
    data_dir = Path("data/processed_packet_aligned")
    labels = ["benign", "botnet", "ddos"]
    
    for label in labels:
        class_dir = data_dir / label
        if not class_dir.exists():
            print(f"Directory missing: {class_dir}")
            continue
            
        images = list(class_dir.glob("*.png"))
        num_images = len(images)
        
        if num_images == 0:
            print(f"Class: {label} - No images found.")
            continue
            
        # Check first image for dimensions and mode
        sample_img = Image.open(images[0])
        mode = sample_img.mode
        dimensions = sample_img.size
        
        print(f"Class: {label}")
        print(f"  Images generated:  {num_images}")
        print(f"  Dimensions:        {dimensions[0]}x{dimensions[1]}")
        print(f"  Mode:              {mode}")
        
        stats_file = class_dir / f"{label}_stats.json"
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                lengths = json.load(f)
            
            padded = sum(1 for l in lengths if l < 4096)
            truncated = sum(1 for l in lengths if l > 4096)
            exact = sum(1 for l in lengths if l == 4096)
            
            print(f"  Packet Stats:")
            print(f"    Avg length: {sum(lengths)/len(lengths):.2f} bytes")
            print(f"    Padded (<4096):    {padded} ({(padded/len(lengths))*100:.2f}%)")
            print(f"    Truncated (>4096): {truncated} ({(truncated/len(lengths))*100:.2f}%)")
            print(f"    Exact (==4096):    {exact} ({(exact/len(lengths))*100:.2f}%)")
        print()
        
if __name__ == "__main__":
    main()
