# data_processing/

**Syllabus:** Unit II — Data Link framing  
**Owner:** _assign member_

## Responsibility

1. Ingest PCAP / binary frame streams from `data/raw/`.
2. Convert byte sequences into fixed-size **2D grayscale arrays (images)**.
3. Write labeled outputs to `data/processed/`.

## Handoff

- **Consumes:** `data/raw/`
- **Produces:** `data/processed/` (input for `ml/`)

## Suggested modules (to implement)

- `pcap_reader.py` — frame/byte extraction
- `image_transform.py` — binary → 2D grayscale
- `batch_convert.py` — dataset conversion CLI
