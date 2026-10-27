# Dataset attribution

- **CTU-13:** Sebastian Garcia, Martin Grill, Jan Stiborek and Alejandro Zunino. “An empirical comparison of botnet detection methods.” Computers & Security 45 (2014), 100–123. [DOI](https://doi.org/10.1016/j.cose.2014.05.011), [dataset](https://www.stratosphereips.org/datasets-ctu13).
- **CTU normal captures:** Sebastian Garcia, Malware Capture Facility Project / Stratosphere Laboratory. [Normal datasets](https://www.stratosphereips.org/datasets-normal), including CTU-Normal-4-only-DNS and the scenario-9 normal capture.
- **CIC-IDS2017:** Iman Sharafaldin, Arash Habibi Lashkari and Ali A. Ghorbani. “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.” ICISSP 2018. [Original dataset and schedules](https://www.unb.ca/cic/datasets/ids-2017.html). PCAP byte ranges were obtained through the [bvsam mirror](https://huggingface.co/datasets/bvsam/cic-ids-2017).
- **CSE-CIC-IDS2018:** Communications Security Establishment and Canadian Institute for Cybersecurity, University of New Brunswick. [Dataset](https://www.unb.ca/cic/datasets/ids-2018.html), [AWS Open Data registry](https://registry.opendata.aws/cse-cic-ids2018/).
- **MAWI:** WIDE Project, MAWI Working Group Traffic Archive, samplepoint-F, 1 January 2024. [Archive](https://mawi.wide.ad.jp/mawi/). The acquired excerpt is unlabeled and is not treated as verified benign traffic.

Downloaded artifacts, their exact origins, selected ranges, hashes, and label limitations are recorded locally in `data/external/acquisition.json` and per-source `source.json` records. Downloaded PCAPs are excluded from Git.
