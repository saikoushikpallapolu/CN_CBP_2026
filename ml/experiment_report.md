# PCAP Sampling Experiment Report

## Overview
This experiment evaluated whether broader, uniform sampling across the valid portions of the 100-MiB PCAP slices improves the CNN's generalization compared to sequentially taking the first 2,000 windows. The dataset is derived from three 100-MiB slices (one PCAP per class) and does not represent a general CIC-IDS2017 benchmark.

## Evaluation Methodology
- **Train/Val/Test Split:** Chronological split for each class (1,400 train, 300 validation, 300 test)
- **Model:** TrafficCNN
- **Parameters:** 4,096-byte non-overlapping windows -> 64x64 Grayscale, Adam optimizer (lr=0.001), 30 epochs (patience=7)

## Results Comparison

### Existing Sequential Dataset (Baseline)
*The first 8.2MB of the PCAP processed sequentially.*
- **Test Accuracy:** 57.44%
- **Macro F1:** 0.5167
- **Per-class metrics:**
  - **Benign:** Precision: 0.3895 | Recall: 0.1233 | F1: 0.1873
  - **Botnet:** Precision: 0.5258 | Recall: 0.6800 | F1: 0.5930
  - **DDoS:**   Precision: 0.6619 | Recall: 0.9200 | F1: 0.7699

### New Broader-Sampled Dataset (Experiment)
*Uniform sampling of 2,000 windows across the entire ~100MB of valid byte stream.*
- **Test Accuracy:** 41.11%
- **Macro F1:** 0.3014
- **Per-class metrics:**
  - **Benign:** Precision: 1.0000 | Recall: 0.0167 | F1: 0.0328
  - **Botnet:** Precision: 0.4433 | Recall: 0.9900 | F1: 0.6124
  - **DDoS:**   Precision: 0.3022 | Recall: 0.2267 | F1: 0.2590

## Conclusion
Broader sampling across the PCAP **did not improve performance**; in fact, it significantly degraded the model's accuracy and Macro F1 score.

### Observations:
- **Catastrophic Drop in DDoS:** The F1 score for DDoS dropped massively from ~0.77 to ~0.26. The model confused nearly 50% of the DDoS test samples with Botnet.
- **Benign Overfitting/Underfitting:** The model practically failed to identify Benign traffic at all (only ~1.6% recall).
- **Hypothesis:** Because we only have a single PCAP slice per class, the traffic characteristics might drift or change drastically throughout the later parts of the capture (e.g., the attack phases might be concentrated at specific chronological points). By sampling uniformly across the whole file, the train, validation, and test splits ended up covering very different traffic profiles, breaking the temporal locality that the original sequential extraction benefited from.

**Recommendation:** Do not use the broader-sampled dataset for production. The model is struggling heavily with the variance introduced by the sampling method across a single source PCAP.
