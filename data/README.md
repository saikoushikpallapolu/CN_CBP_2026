# data/

Shared datasets for the pipeline. Large binaries are **not** committed (see root `.gitignore`).

| Subfolder | Contents |
|-----------|----------|
| `raw/benign/` | Original benign PCAP files |
| `raw/ddos/` | Original DDoS / DoS PCAP files |
| `raw/botnet/` | Original botnet PCAP files |
| `processed/benign/` | 64×64 grayscale images (benign) |
| `processed/ddos/` | 64×64 grayscale images (ddos) |
| `processed/botnet/` | 64×64 grayscale images (botnet) |

## Dataset source (Phase 1B)

- **Official page:** https://www.unb.ca/cic/datasets/ids-2017.html  
- **Paper to cite:** Sharafaldin, Lashkari, Ghorbani — ICISSP 2018  
- **Practical mirror used for slices:** Hugging Face `bvsam/cic-ids-2017`  
  https://huggingface.co/datasets/bvsam/cic-ids-2017  

UNB full day PCAPs are ~8–13 GB each. For Phase 1 we use **100 MB slices** (first bytes of each day file) so the pipeline can start without multi-hour downloads.

## Files currently in `data/raw/` (local only — not in git)

| Label | File | Approx size | CIC day |
|-------|------|-------------|---------|
| benign | `Monday-WorkingHours_slice100MB.pcap` | 100 MB | Monday (benign day) |
| ddos | `Wednesday-workingHours_slice100MB.pcap` | 100 MB | Wednesday (DoS / DDoS day) |
| botnet | `Friday-WorkingHours_slice100MB.pcap` | 100 MB | Friday (Botnet ARES + later DDoS) |

**Note:** These are the **start** of each day capture (PCAPNG format). Monday start is clean benign. Wednesday/Friday starts may mix early-day traffic before the exact attack windows; good enough to build and train a first model. For stricter labels later, replace with full-day downloads or time-filtered extracts from UNB.

## How you get FULL day files yourself (optional later)

1. Open https://www.unb.ca/cic/datasets/ids-2017.html  
2. Click **Download this dataset** → fill the form (use a complete email, e.g. `...@gmail.com`)  
3. Download Monday / Wednesday / Friday PCAPs (slow; use a download manager)  
4. Replace the slice files in `data/raw/<label>/`
