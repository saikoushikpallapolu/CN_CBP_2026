# PCAP-to-Image Malware Fingerprinting

**Syllabus mapping:** Unit V (Network Security), Unit II (Data Link framing)

Convert raw network frames into 2D grayscale images and train a CNN to distinguish benign traffic from DDoS / Botnet activity.

## Pipeline

```
PCAP binary stream → 2D grayscale images → CNN (TF/PyTorch) → Benign | DDoS | Botnet
```

## Repo layout

| Folder | Responsibility |
|--------|----------------|
| `data/` | Raw PCAPs and generated traffic images (large files gitignored) |
| `data_processing/` | Frame capture + binary → 2D grayscale transform (Unit II) |
| `ml/` | CNN architecture, training, evaluation |
| `classification/` | Inference + benign vs malicious reporting |
| `docs/` | Abstract, design notes, syllabus mapping |
| `notebooks/` | Experiments and exploration |
| `scripts/` | End-to-end runners |

## Collaboration

- Work on **feature branches**, open PRs into `main`.
- Prefer owning a **module**, not a personal folder. Cross-module PRs are expected at integration points.
- Suggested branch names: `feat/pcap-to-image`, `feat/cnn-train`, `feat/inference`.

## Setup (later)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Start here (team)

Read **[docs/TEAM_GUIDE.txt](docs/TEAM_GUIDE.txt)** before coding — problem, architecture, roles, build order, and terms explained simply.

## Status

Scaffold only — implementation next.
