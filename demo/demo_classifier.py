"""
demo/demo_classifier.py - Demo mapping for presentation
"""
import os
import base64
from typing import Dict, Any

from demo.demo_config import get_demo_label_for_image

def predict_demo_image(filename: str, image_bytes: bytes) -> Dict[str, Any]:
    label = get_demo_label_for_image(filename)
    
    # Return fake high probabilities
    if label == "benign":
        probs = {"benign": 0.985, "botnet": 0.010, "ddos": 0.005}
        color = "#10b981"
        level = "LOW"
    elif label == "botnet":
        probs = {"benign": 0.005, "botnet": 0.991, "ddos": 0.004}
        color = "#f59e0b"
        level = "HIGH"
    else:
        label = "ddos"
        probs = {"benign": 0.001, "botnet": 0.010, "ddos": 0.989}
        color = "#ef4444"
        level = "CRITICAL"
        
    encoded = base64.b64encode(image_bytes).decode("utf-8")
    data_uri = f"data:image/png;base64,{encoded}"

    return {
        "prediction": label,
        "confidence_pct": round(max(probs.values()) * 100, 1),
        "probabilities": probs,
        "risk_level": level,
        "risk_color": color,
        "image_64": data_uri,
        "image_zoomed": data_uri, # Real API might zoom it, but for demo we just pass it back
        "telemetry": {
            "entropy": 7.1 if label != "benign" else 3.2,
            "total_bytes_received": len(image_bytes),
            "mean_byte": 128.5
        },
        "hex_dump": ["00 11 22 33 44 55 (Demo Hex Dump)"],
        "demo_mode": True
    }
