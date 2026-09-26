# Phase 1 handoff — Data Processing → ML

**Status:** Phase 1 complete. Images are ready for Member 2.

## What to load

| Item | Value |
|------|--------|
| Image size | **64 × 64** grayscale (`mode=L`) |
| Bytes per image | **4096** |
| Labels (folder names) | `benign`, `ddos`, `botnet` |
| Path | `data/processed/<label>/*.png` |

## Image counts (current batch)

| Label | Count | Example files |
|-------|------:|---------------|
| benign | 2000 | `data/processed/benign/benign_0001.png` … `benign_2000.png` |
| ddos | 2000 | `data/processed/ddos/ddos_0001.png` … `ddos_2000.png` |
| botnet | 2000 | `data/processed/botnet/botnet_0001.png` … `botnet_2000.png` |

**Total:** 6000 images.

## Suggested split (Phase 2)

Use stratified split by class:

- **70% train** / **15% validation** / **15% test**

## Source notes

- Raw PCAPs: CIC-IDS2017 slices under `data/raw/<label>/` (see `data/README.md`)
- Conversion: non-overlapping 4096-byte windows of original frame bytes → PNG
- Framework for ML (locked): **PyTorch**
- Accuracy target: **≥ 90%** test accuracy + per-class F1

## How Member 1 regenerates images

```powershell
.\.venv\Scripts\Activate.ps1
python data_processing/batch_convert.py --max-images-per-class 2000
```

## How to visually demo one PCAP

```powershell
python scripts/demo_pcap_to_image.py path\to\your.pcap
```

This prints a byte preview and opens the 64×64 grayscale image.
