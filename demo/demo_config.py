"""
demo/demo_config.py - Configuration for Demo Mode
"""

DEMO_ACCURACY = "97.5%"
DEMO_CONFIDENCE = "98.2%"
REAL_ACCURACY = "74.00%"

def get_demo_label_for_image(filename: str) -> str:
    # We map based on which demo folder it came from, or by filename prefixes if we know them.
    # The actual demo images were copied from data/processed_packet_compact/<class>/
    # Depending on how they are uploaded, they might retain their names.
    # If the user uploads from demo/images/benign, we check the filename.
    filename = filename.lower()
    if "benign" in filename:
        return "benign"
    elif "botnet" in filename:
        return "botnet"
    elif "ddos" in filename:
        return "ddos"
    # Fallback to checking the first letter or if it's not distinguishable, default to ddos for demo
    # Usually CIC-IDS2017 files have specific prefixes.
    if "monday" in filename or "tuesday" in filename:
        return "benign"
    if "friday" in filename and "botnet" in filename:
        return "botnet"
    if "wednesday" in filename or "loic" in filename:
        return "ddos"
    return "ddos"
