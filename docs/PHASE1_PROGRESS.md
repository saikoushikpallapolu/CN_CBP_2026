# Phase 1 Progress Tracker — Data Processing (Member 1)

**Owner:** Role A (`data_processing/`)  
**Goal of Phase 1:** Turn sample PCAPs into labeled 64×64 grayscale images under `data/processed/` so Member 2 can train the CNN.

## Locked rules (from `docs/design.md`)

- Image size: **64 × 64** (needs exactly **4096** bytes per sample)
- Labels / folders: `benign` | `ddos` | `botnet`
- Raw PCAPs: `data/raw/<label>/`
- Output images: `data/processed/<label>/`
- Each byte (0–255) = one pixel; pad with 0 or truncate to 4096

**How to use:** Change `[ ]` to `[x]` when a step is fully done.  
**Order:** 1A → 1B → 1C → 1D → 1E → 1F → 1G.

---

## PHASE 1A — Setup (tools and folders ready)

**Goal:** Your computer is ready to work on data processing.

- [x] **1A.1** Confirm project folders exist (`data/raw`, `data/processed`, `data_processing`, `docs`, etc.)
- [x] **1A.2** Create label folders for raw captures: `data/raw/benign/`, `data/raw/ddos/`, `data/raw/botnet/`
- [x] **1A.3** Create label folders for output images: `data/processed/benign/`, `data/processed/ddos/`, `data/processed/botnet/`
- [x] **1A.4** Update `requirements.txt` for Phase 1 packages (`numpy`, `Pillow`, `scapy`)
- [x] **1A.5** Create a Python virtual environment (`.venv`) in the project root
- [x] **1A.6** Activate `.venv` and install Phase 1 packages from `requirements.txt`
- [x] **1A.7** Smoke test: in Python, `import numpy`, `PIL`, `scapy` successfully
- [x] **1A.8** Mark Phase 1A done in this file

**1A completed:** 2026-09-26 — Python 3.13.5, numpy 2.5.3, Pillow 12.3.0, scapy 2.7.0

---

## PHASE 1B — Get small sample data

**Goal:** You have a few PCAP files for each class sitting in the right folders.

- [x] **1B.1** Read `data/README.md` and decide where CIC-IDS2017 samples come from (write the download/source link in `data/README.md`)
- [x] **1B.2** Download or copy a SMALL benign sample PCAP → `data/raw/benign/`
- [x] **1B.3** Download or copy a SMALL ddos sample PCAP → `data/raw/ddos/`
- [x] **1B.4** Download or copy a SMALL botnet sample PCAP → `data/raw/botnet/`
- [x] **1B.5** List the files in each `data/raw/<label>/` folder and confirm at least one file per class
- [x] **1B.6** Note in `data/README.md`: file names, which CIC day/scenario, and that files are local (not committed to git)

**1B completed:** 2026-09-26 — 100 MB CIC-IDS2017 slices (Monday/Wednesday/Friday) via Hugging Face mirror; documented in `data/README.md`.

---

## PHASE 1C — Read a PCAP and get bytes

**Goal:** Code can open one PCAP and give you a list of numbers (bytes).

- [x] **1C.1** Create the file `data_processing/pcap_reader.py`
- [x] **1C.2** Write a function that opens one `.pcap` file (using scapy)
- [x] **1C.3** From that file, collect raw bytes from packets/frames into one long byte list
- [x] **1C.4** Add a tiny test/main: run the reader on ONE sample PCAP and print how many bytes you got
- [x] **1C.5** Confirm: you see a byte count printed (not an error)

**1C completed:** 2026-09-26 — `extract_bytes_from_pcap()` works on benign/ddos/botnet slices (PCAPNG). Smoke tests: 100 packets benign → 13,591 bytes; missing file errors cleanly.

---

## PHASE 1D — Turn bytes into ONE grayscale image

**Goal:** One byte list becomes one 64×64 PNG image.

- [x] **1D.1** Create the file `data_processing/image_transform.py`
- [x] **1D.2** Write a function: take bytes → keep first 4096 (pad with 0 if shorter, cut if longer)
- [x] **1D.3** Write a function: reshape those 4096 values into a 64×64 grid
- [x] **1D.4** Write a function: save that grid as a grayscale PNG (using Pillow)
- [x] **1D.5** Test: take bytes from one PCAP → save ONE test PNG
- [x] **1D.6** Open/verify the PNG: 64×64, mode `L`, not corrupt

**1D completed:** 2026-09-26 — test PNG verified `(64, 64) L`.

---

## PHASE 1E — Batch convert all samples

**Goal:** Many PCAPs become many labeled images automatically.

- [x] **1E.1** Create the file `data_processing/batch_convert.py`
- [x] **1E.2** For each label folder (`benign`, `ddos`, `botnet`): read every PCAP in `data/raw/<label>/`
- [x] **1E.3** For each PCAP: bytes → 64×64 images → `data/processed/<label>/`
- [x] **1E.4** Use clear image file names (e.g. `benign_0001.png`)
- [x] **1E.5** Run the batch converter once end-to-end
- [x] **1E.6** Confirm images exist in all three processed folders

**1E completed:** 2026-09-26 — 2000 images per class (6000 total).

---

## PHASE 1F — Quality check

**Goal:** Prove the images are good enough for Member 2 to train on.

- [x] **1F.1** Count how many images are in each `data/processed/<label>/` folder:
  - benign: **2000**
  - ddos: **2000**
  - botnet: **2000**
- [x] **1F.2** Open/check at least 2 images from EACH class; confirm they open
- [x] **1F.3** Confirm checked images are 64×64 and grayscale (`L`)
- [x] **1F.4** Confirm not all-black (pixel max 255, means ~64–127 across samples)
- [x] **1F.5** No converter bugs found that required a re-run

**1F completed:** 2026-09-26 — quality script `QUALITY_OK`.

---

## PHASE 1G — Handoff to Member 2 (ML)

**Goal:** Member 2 knows exactly what to load and how it is labeled.

- [x] **1G.1** Write `data_processing/HANDOFF.md` (size, paths, labels, counts)
- [x] **1G.2** Update `data_processing/README.md` with how to run the converter
- [x] **1G.3** Demo script ready: `scripts/demo_pcap_to_image.py` (Member 2: Phase 1 images are ready)
- [x] **1G.4** Mark ALL of Phase 1 complete below

**1G completed:** 2026-09-26

---

## Phase 1 complete?

- [x] Phase 1A done
- [x] Phase 1B done
- [x] Phase 1C done
- [x] Phase 1D done
- [x] Phase 1E done
- [x] Phase 1F done
- [x] Phase 1G done
- [x] **PHASE 1 FULLY COMPLETE** — Member 2 can start Phase 2

---

## Notes / blockers

- Phase 1A–1G finished 2026-09-26.
- Raw: 100 MB CIC-IDS2017 slices in `data/raw/{benign,ddos,botnet}/`.
- Processed: 2000 × 64×64 PNGs per class in `data/processed/`.
- Visual demo: `python scripts/demo_pcap_to_image.py <your.pcap>`
