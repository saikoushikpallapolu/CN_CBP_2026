# classification/

**Owner:** _assign member_

## Responsibility

1. Load a trained model from `ml/checkpoints/`.
2. Run inference on new traffic images (or live/batch PCAP → image via `data_processing/`).
3. Report **Benign** vs **Malicious** (DDoS / Botnet) in a clear output format.

## Handoff

- **Consumes:** `ml/checkpoints/` + images from `data/processed/` (or on-the-fly transform)
- **Produces:** predictions / reports (CLI print, CSV, or simple dashboard later)

## Suggested modules (to implement)

- `infer.py` — single/batch prediction
- `report.py` — human-readable summary (benign / DDoS / botnet)
