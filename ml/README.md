# ml/

**Syllabus:** Unit V — Network Security (ML detection path)  
**Owner:** _assign member_

## Responsibility

1. Define CNN architecture (TensorFlow **or** PyTorch — pick one for the team).
2. Train on images from `data/processed/`.
3. Evaluate accuracy / confusion matrix for benign vs DDoS vs Botnet.
4. Save checkpoints under `checkpoints/` (gitignored).

## Handoff

- **Consumes:** `data/processed/`
- **Produces:** trained weights in `checkpoints/` → used by `classification/`

## Suggested modules (to implement)

- `dataset.py` — load grayscale traffic images + labels
- `model.py` — CNN definition
- `train.py` — training loop
- `evaluate.py` — metrics on hold-out set
