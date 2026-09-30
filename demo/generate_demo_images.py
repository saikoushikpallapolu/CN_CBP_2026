import os
import random
import shutil
from pathlib import Path

def generate_demo_images():
    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    src_data_dir = project_root / "data" / "processed_packet_compact"
    
    classes = ["benign", "botnet", "ddos"]
    num_examples_per_class = 15
    
    # Use fixed seed for reproducibility
    random.seed(42)
    
    # Check if images already exist
    all_exist = True
    for cls in classes:
        target_dir = base_dir / cls
        if not target_dir.exists():
            all_exist = False
            break
        # Check if there are enough examples
        existing_images = list(target_dir.glob("*.png"))
        if len(existing_images) < num_examples_per_class:
            all_exist = False
            break
            
    if all_exist:
        print("Demo images already exist — skipping generation.")
        return
        
    print("Generating static demo images...")
    
    for cls in classes:
        target_dir = base_dir / cls
        target_dir.mkdir(parents=True, exist_ok=True)
        
        src_dir = src_data_dir / cls
        if not src_dir.exists():
            print(f"Warning: source directory {src_dir} does not exist. Skipping {cls}.")
            continue
            
        src_images = list(src_dir.glob("*.png"))
        if not src_images:
            print(f"Warning: No images found in {src_dir}. Skipping {cls}.")
            continue
            
        # Select random images
        selected_images = random.sample(src_images, min(len(src_images), num_examples_per_class))
        
        for idx, src_img in enumerate(selected_images, start=1):
            target_img = target_dir / f"example_{idx:03d}.png"
            if not target_img.exists():
                shutil.copy2(src_img, target_img)
                
    print(f"Demo image generation complete. Generated up to {num_examples_per_class} images per class.")

if __name__ == "__main__":
    generate_demo_images()
