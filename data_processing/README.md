# data_processing/

**Syllabus:** Unit II — Data Link framing  
**Owner:** Role A (Member 1)

## Responsibility

1. Ingest PCAP / binary frame streams from `data/raw/`.
2. Convert byte sequences into fixed-size **2D grayscale arrays (images)**.
3. Write labeled outputs to `data/processed/`.

## Handoff

- **Consumes:** `data/raw/`
- **Produces:** `data/processed/` (input for `ml/`)
- See **[HANDOFF.md](HANDOFF.md)** for Member 2 details.

## Modules

| File | Status | Role |
|------|--------|------|
| `pcap_reader.py` | Done (1C) | PCAP/PCAPNG → raw frame byte stream |
| `image_transform.py` | Done (1D) | bytes → 64×64 grayscale PNG |
| `batch_convert.py` | Done (1E) | convert whole `data/raw/` tree |

## Commands

Activate the venv first:

```powershell
.\.venv\Scripts\Activate.ps1
```

**Read one PCAP (byte count):**

```powershell
python data_processing/pcap_reader.py data/raw/benign/Monday-WorkingHours_slice100MB.pcap --max-packets 100
```

**One PCAP → one PNG:**

```powershell
python data_processing/image_transform.py data/raw/benign/Monday-WorkingHours_slice100MB.pcap -o data/processed/benign/test_sample.png
```

**Batch convert all classes (default 2000 images each):**

```powershell
python data_processing/batch_convert.py --max-images-per-class 2000
```

**See it working (bytes printed + image opens):**

```powershell
python scripts/demo_pcap_to_image.py data/raw/benign/Monday-WorkingHours_slice100MB.pcap
```

Drop any `.pcap` / `.pcapng` path after the script name to try your own file.
