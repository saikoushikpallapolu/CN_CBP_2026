# Design notes — locked starter decisions

Fill-ins from the team guide. Change only if the whole team agrees.

## 1. Image size: **64 × 64**

Why: One image = 4096 bytes — enough structure for a CNN, still light on a laptop.

## 2. Byte → pixel method

1. Take one sample (recommended: one **flow** or a fixed **time/byte window** of traffic).
2. Read raw bytes (prefer full frame bytes so Unit II framing stays visible).
3. Keep the **first 4096** bytes; **pad with 0** if shorter; **truncate** if longer.
4. Each byte value `0–255` becomes one grayscale pixel.
5. Reshape **row-major** into shape `(64, 64)`.
6. Save as PNG under `data/processed/<label>/`.

Why: Simple, standard “traffic/malware as image” method; easy to explain in a viva.

## 3. Classes: **benign / ddos / botnet** (3-class)

Folder names (keep exact):

- `data/processed/benign/`
- `data/processed/ddos/`
- `data/processed/botnet/`

Why: Matches the project abstract/poster; binary would hide DDoS vs Botnet.

## 4. Framework: **PyTorch**

Why: You see the training steps clearly while learning; stick to one stack for the whole team.

## 5. Dataset source: **CIC-IDS2017** (small subset first)

- Start with limited captures/samples for: Benign, one DDoS type, Botnet.
- Prefer real PCAPs when practical; if files are huge, begin with a tiny curated slice, then grow.
- Document the exact download link and which days/scenarios you used in `data/README.md`.

**Split (after you have images):** train 70% / validation 15% / test 15% (stratified by class).

Why: Public dataset with the labels we need; small-first avoids weeks of download before any learning.

## 6. Success target

- **Test accuracy ≥ 90%** (submission / approval bar)
- Also report **F1 per class** (benign, ddos, botnet)
- Optional later: confusion matrix + false-positive rate on benign

Why: 90%+ is demo-ready for evaluation, not just “better than random”; F1 keeps all classes honest.

## Checklist

- [x] Image size
- [x] Byte → pixel method
- [x] Label scheme
- [x] Framework
- [x] Dataset source + split plan
- [x] Success metrics
