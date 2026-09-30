"""
classification/infer.py - End-to-end inference engine for PCAP-to-Image malware fingerprinting.
"""

from __future__ import annotations

import base64
import io
import math
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image
import torch
import torch.nn.functional as F
from torchvision import transforms

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.model import TrafficCNN
from data_processing.image_transform import BYTES_PER_IMAGE, IMAGE_HEIGHT, IMAGE_WIDTH, pad_or_truncate
from data_processing.pcap_reader import extract_bytes_from_pcap


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0 to 8)."""
    if not data:
        return 0.0
    occ = [0] * 256
    for b in data:
        occ[b] += 1
    length = len(data)
    entropy = 0.0
    for count in occ:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def format_hex_dump(data: bytes, max_bytes: int = 128) -> list[str]:
    """Format bytes into canonical hex dump rows."""
    preview = data[:max_bytes]
    lines = []
    for i in range(0, len(preview), 16):
        chunk = preview[i:i + 16]
        hex_col = " ".join(f"{b:02x}" for b in chunk)
        ascii_col = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_col:<48}  |{ascii_col}|")
    return lines


class TrafficClassifier:
    def __init__(self, checkpoint_path: str | Path | None = None, device: str | None = None):
        if checkpoint_path is None:
            checkpoint_path = PROJECT_ROOT / "ml" / "checkpoints" / "packet_compact_model.pth"
        
        self.checkpoint_path = Path(checkpoint_path)
        if not self.checkpoint_path.is_file():
            raise FileNotFoundError(f"Model checkpoint not found at: {self.checkpoint_path}")

        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        # Load weights
        checkpoint = torch.load(str(self.checkpoint_path), map_location=self.device)
        self.classes = checkpoint.get("classes", ["benign", "botnet", "ddos"])
        
        self.model = TrafficCNN(num_classes=len(self.classes)).to(self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()

        self.transform = transforms.Compose([
            transforms.Grayscale(num_output_channels=1),
            transforms.ToTensor(),
            transforms.Normalize((0.5,), (0.5,))
        ])

    def predict_bytes(self, raw_bytes: bytes, packet_count: int | None = None) -> dict[str, Any]:
        """Convert byte stream to 64x64 image and run TrafficCNN classification."""
        total_len = len(raw_bytes)
        
        # 1. Pad or truncate to 4096 bytes
        fixed_bytes = pad_or_truncate(raw_bytes, BYTES_PER_IMAGE)
        arr_2d = np.frombuffer(fixed_bytes, dtype=np.uint8).reshape((IMAGE_HEIGHT, IMAGE_WIDTH))
        
        # 2. Create PIL Image
        pil_img = Image.fromarray(arr_2d, mode="L")
        
        # Base64 string of original 64x64
        buf_64 = io.BytesIO()
        pil_img.save(buf_64, format="PNG")
        b64_64 = "data:image/png;base64," + base64.b64encode(buf_64.getvalue()).decode("utf-8")

        # Base64 string of zoomed 512x512 preview (nearest-neighbor)
        zoomed_img = pil_img.resize((512, 512), resample=Image.Resampling.NEAREST)
        buf_512 = io.BytesIO()
        zoomed_img.save(buf_512, format="PNG")
        b64_512 = "data:image/png;base64," + base64.b64encode(buf_512.getvalue()).decode("utf-8")

        # 3. Model Inference
        tensor = self.transform(pil_img).unsqueeze(0).to(self.device)
        with torch.no_grad():
            logits = self.model(tensor)
            probs = F.softmax(logits, dim=1).squeeze().tolist()
            pred_idx = int(torch.argmax(logits, dim=1).item())

        predicted_class = self.classes[pred_idx]
        confidence = probs[pred_idx]

        probability_dict = {
            cls_name: round(prob, 4)
            for cls_name, prob in zip(self.classes, probs)
        }

        # 4. Byte stats & hex dump
        entropy = calculate_entropy(fixed_bytes)
        hex_dump = format_hex_dump(raw_bytes, max_bytes=128)

        # Risk level determination
        if predicted_class == "benign":
            risk_level = "LOW"
            risk_color = "#10b981"  # Emerald
        elif predicted_class == "botnet":
            risk_level = "HIGH"
            risk_color = "#f59e0b"  # Amber
        else:
            risk_level = "CRITICAL"
            risk_color = "#ef4444"  # Red

        return {
            "prediction": predicted_class,
            "confidence": round(confidence, 4),
            "confidence_pct": round(confidence * 100, 1),
            "risk_level": risk_level,
            "risk_color": risk_color,
            "probabilities": probability_dict,
            "image_64": b64_64,
            "image_zoomed": b64_512,
            "telemetry": {
                "total_bytes_received": total_len,
                "bytes_fingerprinted": BYTES_PER_IMAGE,
                "packet_count": packet_count if packet_count is not None else "N/A",
                "entropy": entropy,
                "min_byte": int(arr_2d.min()),
                "max_byte": int(arr_2d.max()),
                "mean_byte": round(float(arr_2d.mean()), 1),
            },
            "hex_dump": hex_dump,
        }

    def predict_packet_compact_bytes(self, raw_bytes: bytes, packet_count: int | None = None) -> dict[str, Any]:
        """Convert byte stream to 20x20 image and run TrafficCNN classification."""
        total_len = len(raw_bytes)
        
        COMPACT_BYTES = 400
        COMPACT_SIZE = 20
        
        # 1. Pad or truncate to 400 bytes
        fixed_bytes = raw_bytes[:COMPACT_BYTES]
        if len(fixed_bytes) < COMPACT_BYTES:
            fixed_bytes += b"\x00" * (COMPACT_BYTES - len(fixed_bytes))
            
        arr_2d = np.frombuffer(fixed_bytes, dtype=np.uint8).reshape((COMPACT_SIZE, COMPACT_SIZE))
        
        # 2. Create PIL Image
        pil_img = Image.fromarray(arr_2d, mode="L")
        
        # Base64 string of original 20x20
        buf_20 = io.BytesIO()
        pil_img.save(buf_20, format="PNG")
        b64_20 = "data:image/png;base64," + base64.b64encode(buf_20.getvalue()).decode("utf-8")

        # Base64 string of zoomed 512x512 preview (nearest-neighbor)
        zoomed_img = pil_img.resize((512, 512), resample=Image.Resampling.NEAREST)
        buf_512 = io.BytesIO()
        zoomed_img.save(buf_512, format="PNG")
        b64_512 = "data:image/png;base64," + base64.b64encode(buf_512.getvalue()).decode("utf-8")

        # 3. Model Inference
        tensor = self.transform(pil_img).unsqueeze(0).to(self.device)
        with torch.no_grad():
            logits = self.model(tensor)
            probs = F.softmax(logits, dim=1).squeeze().tolist()
            pred_idx = int(torch.argmax(logits, dim=1).item())

        predicted_class = self.classes[pred_idx]
        confidence = probs[pred_idx]

        probability_dict = {
            cls_name: round(prob, 4)
            for cls_name, prob in zip(self.classes, probs)
        }

        # 4. Byte stats & hex dump
        entropy = calculate_entropy(fixed_bytes)
        hex_dump = format_hex_dump(raw_bytes, max_bytes=128)

        # Risk level determination
        if predicted_class == "benign":
            risk_level = "LOW"
            risk_color = "#10b981"  # Emerald
        elif predicted_class == "botnet":
            risk_level = "HIGH"
            risk_color = "#f59e0b"  # Amber
        else:
            risk_level = "CRITICAL"
            risk_color = "#ef4444"  # Red

        return {
            "prediction": predicted_class,
            "confidence": round(confidence, 4),
            "confidence_pct": round(confidence * 100, 1),
            "risk_level": risk_level,
            "risk_color": risk_color,
            "probabilities": probability_dict,
            "image_64": b64_20,
            "image_zoomed": b64_512,
            "telemetry": {
                "total_bytes_received": total_len,
                "bytes_fingerprinted": COMPACT_BYTES,
                "packet_count": packet_count if packet_count is not None else "N/A",
                "entropy": entropy,
                "min_byte": int(arr_2d.min()),
                "max_byte": int(arr_2d.max()),
                "mean_byte": round(float(arr_2d.mean()), 1),
            },
            "hex_dump": hex_dump,
        }

    def predict_pcap_file(self, file_path: str | Path, max_bytes: int = 4096) -> dict[str, Any]:
        """Read a PCAP file and run prediction."""
        if self.checkpoint_path.name == "packet_compact_model.pth":
            raw_bytes = extract_bytes_from_pcap(file_path, max_packets=1)
            return self.predict_packet_compact_bytes(raw_bytes, packet_count=1)
        
        raw_bytes = extract_bytes_from_pcap(file_path, max_bytes=max_bytes)
        return self.predict_bytes(raw_bytes)

    def predict_uploaded_file(self, file_content: bytes, filename: str) -> dict[str, Any]:
        """Handle uploaded file: either PCAP or direct PNG/JPG image."""
        import tempfile
        ext = filename.lower().split(".")[-1] if "." in filename else ""
        
        is_packet_compact = self.checkpoint_path.name == "packet_compact_model.pth"
        
        if ext in ["pcap", "pcapng", "cap"]:
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
                    tmp.write(file_content)
                    temp_path = tmp.name
                try:
                    res = self.predict_pcap_file(temp_path)
                except Exception:
                    # Fallback to direct raw bytes if pcap header parsing fails
                    if is_packet_compact:
                        res = self.predict_packet_compact_bytes(file_content)
                    else:
                        res = self.predict_bytes(file_content)
                res["filename"] = filename
                return res
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
        elif ext in ["png", "jpg", "jpeg", "bmp"]:
            # Direct image upload
            img = Image.open(io.BytesIO(file_content)).convert("L")
            if is_packet_compact:
                if img.size != (20, 20):
                    img = img.resize((20, 20), resample=Image.Resampling.BILINEAR)
                raw_bytes = np.array(img).tobytes()
                res = self.predict_packet_compact_bytes(raw_bytes)
            else:
                if img.size != (IMAGE_WIDTH, IMAGE_HEIGHT):
                    img = img.resize((IMAGE_WIDTH, IMAGE_HEIGHT), resample=Image.Resampling.BILINEAR)
                raw_bytes = np.array(img).tobytes()
                res = self.predict_bytes(raw_bytes)
            res["filename"] = filename
            return res
        else:
            # Fallback treat as raw binary stream
            if is_packet_compact:
                res = self.predict_packet_compact_bytes(file_content)
            else:
                res = self.predict_bytes(file_content)
            res["filename"] = filename
            return res


# Singleton instance for server re-use
_classifier_instance: TrafficClassifier | None = None

def get_classifier() -> TrafficClassifier:
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = TrafficClassifier()
    return _classifier_instance
