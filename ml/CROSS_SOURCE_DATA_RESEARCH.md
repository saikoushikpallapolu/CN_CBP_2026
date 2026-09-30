# Cross-Source Data Research Report

## Current Source A Inventory
- **Benign:** `Monday-WorkingHours_slice100MB.pcap` (CIC-IDS2017, Monday, July 3, 2017)
- **Botnet:** `Friday-WorkingHours_slice100MB.pcap` (CIC-IDS2017, Friday, July 7, 2017 - Botnet ARES morning capture)
- **DDoS:** `Wednesday-workingHours_slice100MB.pcap` (CIC-IDS2017, Wednesday, July 5, 2017 - DoS Hulk/GoldenEye)

---

## Candidate Source B Suitability Review (Subset / Mirror Check)

We evaluated the primary approved Source B candidates to determine if official, manageable PCAP subsets exist that bypass the need for massive >10GB downloads, Torrents, or the AWS CLI.

| Class | Candidate | Dataset | Provenance | Independent? | Download method | Approx size | Label confidence | Official/public source |
|---|---|---|---|---|---|---|---|---|
| Benign | Tuesday-WorkingHours.pcap | CIC-IDS2017 | Tuesday July 4, 2017 | Yes | Full file HTTP download from HuggingFace/UNB | ~11 GB | High | huggingface.co/datasets/bvsam/cic-ids-2017 / UNB |
| Botnet | Botnet-Friday-02-03-2018.pcap | CSE-CIC-IDS2018 | Friday March 2, 2018 (AWS ARES simulation) | Yes | AWS CLI sync from S3 bucket | Massive | High | s3://cse-cic-ids2018/ |
| DDoS | Friday-WorkingHours-Afternoon-DDos.pcap | CIC-IDS2017 | Friday July 7, 2017 (LOIC) | Yes | Full file HTTP download from HuggingFace/UNB | ~8.4 GB | High | huggingface.co/datasets/bvsam/cic-ids-2017 / UNB |

### Findings

1. **No Official PCAP Subsets:** The UNB and community repositories exclusively distribute manageable subsets in **CSV / Parquet formats** (which extract network flow statistics like packet lengths, timings, and header flags). 
2. **Raw PCAP Requirements:** Because our `TrafficCNN` model requires raw binary packet bytes (specifically the first 400 contiguous bytes of each network frame mapped to 20x20 grayscale), flow-level CSV datasets are incompatible with our pipeline.
3. **Download Methods:** The raw PCAPs are only available as massive continuous files (8 to 11+ GB per day). Furthermore, the 2018 Botnet dataset strictly requires the `aws s3` CLI to access the S3 bucket, preventing normal HTTPS browser downloads.

---

## Final Recommendation

We should obtain the following completely independent PCAPs to serve as Source B for Experiment 11:

1. **Benign:** A slice/filtered version of `Tuesday-WorkingHours.pcap` (CIC-IDS2017).
2. **Botnet:** A slice of `Botnet-Friday-02-03-2018.pcap` (CSE-CIC-IDS2018).
3. **DDoS:** A slice of `Friday-WorkingHours-Afternoon-DDos.pcap` (CIC-IDS2017).
