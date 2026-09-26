# Syllabus mapping

| Unit | Topic | Where it shows up in this project |
|------|--------|-----------------------------------|
| **Unit II** | Data Link framing | `data_processing/` — raw frame/byte streams reshaped into 2D grayscale “traffic images” |
| **Unit V** | Network Security | `ml/` + `classification/` — detect DDoS / Botnet vs benign from traffic fingerprints |

## Pipeline ↔ units

```
PCAP DATA INPUT (binary stream)     →  Unit V context (security data source)
DATA TRANSFORM (binary → 2D image)  →  Unit II (framing / byte layout as structure)
CNN + classification                →  Unit V (malware / attack detection)
```
