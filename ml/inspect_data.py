from pathlib import Path
from PIL import Image
import numpy as np

DATA_DIR = Path("data/processed")

for class_name in ["benign", "botnet", "ddos"]:
    files = list((DATA_DIR / class_name).glob("*.png"))

    images = []

    for f in files:
        img = np.array(
            Image.open(f).convert("L"),
            dtype=np.float32
        ) / 255.0

        images.append(img)

    images = np.array(images)

    mean_image = images.mean(axis=0)

    print(f"\n{class_name.upper()}")
    print("Images:", len(files))
    print("Average image mean:", round(images.mean(), 4))
    print("Average image std:", round(images.std(), 4))
    print("Center pixel mean:", round(mean_image[32, 32], 4))
    print("Top-left pixel mean:", round(mean_image[0, 0], 4))
    print("Bottom-right pixel mean:", round(mean_image[63, 63], 4))