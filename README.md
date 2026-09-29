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

## Running the Web Dashboard

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch FastAPI web dashboard
python -m uvicorn api.server:app --reload
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser to inspect PCAP traffic captures and view 2D grayscale fingerprint classifications in real time.

## Start here (team)

Read **[docs/TEAM_GUIDE.txt](docs/TEAM_GUIDE.txt)** and **[notes/PHASE_NOTES.md](notes/PHASE_NOTES.md)** for architecture details and implementation records.

