import os
import json
from pathlib import Path
from PIL import Image
import numpy as np

def main():
    print("Verification Report: Packet Metadata Dataset (20x20)")
    print("=" * 60)
    
    data_dir = Path("data/processed_metadata")
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
        
        # Check pixel range
        arr = np.array(sample_img)
        min_val, max_val = arr.min(), arr.max()
        
        print(f"Class: {label}")
        print(f"  Images generated:  {num_images}")
        print(f"  Dimensions:        {dimensions[0]}x{dimensions[1]}")
        print(f"  Mode:              {mode}")
        print(f"  Pixel Range:       [{min_val}, {max_val}]")
        
        stats_file = class_dir / f"{label}_stats.json"
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                lengths = json.load(f)
            
            print(f"  Packet Stats (Processed {len(lengths)} packets):")
            print(f"    Avg length: {sum(lengths)/len(lengths):.2f} bytes")
            print(f"    Min length: {min(lengths)} bytes")
            print(f"    Max length: {max(lengths)} bytes")
        print()
        
if __name__ == "__main__":
    main()
