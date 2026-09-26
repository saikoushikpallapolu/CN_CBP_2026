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

- [ ] **1C.1** Create the file `data_processing/pcap_reader.py`
- [ ] **1C.2** Write a function that opens one `.pcap` file (using scapy)
- [ ] **1C.3** From that file, collect raw bytes from packets/frames into one long byte list
- [ ] **1C.4** Add a tiny test/main: run the reader on ONE sample PCAP and print how many bytes you got
- [ ] **1C.5** Confirm: you see a byte count printed (not an error)

---

## PHASE 1D — Turn bytes into ONE grayscale image

**Goal:** One byte list becomes one 64×64 PNG image.

- [ ] **1D.1** Create the file `data_processing/image_transform.py`
- [ ] **1D.2** Write a function: take bytes → keep first 4096 (pad with 0 if shorter, cut if longer)
- [ ] **1D.3** Write a function: reshape those 4096 values into a 64×64 grid
- [ ] **1D.4** Write a function: save that grid as a grayscale PNG (using Pillow)
- [ ] **1D.5** Test: take bytes from one PCAP → save ONE test PNG (e.g. `data/processed/benign/test_sample.png`)
- [ ] **1D.6** Open the PNG on your computer and confirm: it opens, looks like a texture, and is 64×64 pixels

---

## PHASE 1E — Batch convert all samples

**Goal:** Many PCAPs become many labeled images automatically.

- [ ] **1E.1** Create the file `data_processing/batch_convert.py`
- [ ] **1E.2** For each label folder (`benign`, `ddos`, `botnet`): read every PCAP in `data/raw/<label>/`
- [ ] **1E.3** For each PCAP (or each sample window): bytes → 64×64 image → save under `data/processed/<label>/`
- [ ] **1E.4** Use clear image file names (e.g. `benign_001.png`)
- [ ] **1E.5** Run the batch converter once end-to-end
- [ ] **1E.6** Confirm images exist in all three processed folders

---

## PHASE 1F — Quality check

**Goal:** Prove the images are good enough for Member 2 to train on.

- [ ] **1F.1** Count images in each `data/processed/<label>/` folder; write counts here:
  - benign: ____
  - ddos: ____
  - botnet: ____
- [ ] **1F.2** Open at least 2 images from EACH class; confirm they open
- [ ] **1F.3** Confirm every checked image is 64×64 and grayscale
- [ ] **1F.4** Confirm no obvious all-black or corrupt files dominate the set
- [ ] **1F.5** Fix any converter bugs found, then re-run batch if needed

---

## PHASE 1G — Handoff to Member 2 (ML)

**Goal:** Member 2 knows exactly what to load and how it is labeled.

- [ ] **1G.1** Write a short handoff note in `data_processing/HANDOFF.md` (image size, folder paths, label names, counts per class)
- [ ] **1G.2** Update `data_processing/README.md` with how to run the converter
- [ ] **1G.3** Tell Member 2: “Phase 1 images are ready”
- [ ] **1G.4** Mark ALL of Phase 1 complete below

---

## Phase 1 complete?

- [x] Phase 1A done
- [x] Phase 1B done
- [ ] Phase 1C done
- [ ] Phase 1D done
- [ ] Phase 1E done
- [ ] Phase 1F done
- [ ] Phase 1G done
- [ ] **PHASE 1 FULLY COMPLETE** — Member 2 can start Phase 2

---

## Notes / blockers

- Phase 1A: created `.venv` and installed Phase 1 packages successfully (smoke test OK).
- Phase 1B: UNB full PCAPs are 8–13 GB and slow; used 100 MB slices from Hugging Face `bvsam/cic-ids-2017` into `data/raw/{benign,ddos,botnet}/`.
- Next: Phase 1C — read PCAP → bytes (`data_processing/pcap_reader.py`).
