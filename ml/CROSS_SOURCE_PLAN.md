# Cross-Source Evaluation Plan

## Future Experiment Design

This plan dictates the strict methodology for evaluating model generalizability once independent data sources are available. Preferably, independent sources will be available for ALL THREE classes.

### 1. Training Setup
- **Training Data:** Exclusively trained on **Source A** (e.g., the current 100-MiB slices).
- **Representation:** 400 bytes, 20x20 grayscale images, strictly one packet per image (0 padding if <400, truncated if >400).
- **Model Architecture:** The existing `TrafficCNN`.

### 2. Validation Setup
- **Validation Data:** Must come exclusively from **Source A**. 
- The completely independent **Source B** must NEVER be used during the validation phase for early stopping, model selection, or hyperparameter tuning.

### 3. Testing / Evaluation Setup
- **Testing Data:** Exclusively evaluated on the completely independent **Source B** (a physically separate PCAP capture).

### 4. Metrics Reporting
- Test Accuracy
- Macro F1
- Weighted F1
- Per-class precision
- Per-class recall
- Per-class F1
- Confusion Matrix

---

## Strict Anti-Leakage Rules

To prevent data contamination and artificial metric inflation, the following rules MUST be adhered to:

1. **No Fake Sources:** Never copy an existing PCAP and treat it as a new "source".
2. **No Random Source Splitting:** Never randomly split packets from the same PCAP and call that "cross-source" (as proven in Experiment 9, this leads to massive data correlation).
3. **Strict Separation:** Never mix Source A and Source B before the train/test split.
4. **Complete Isolation:** The held-out Source B must remain completely unseen during training and model selection.
5. **No Source-B Tuning:** Do not tune hyperparameters using the held-out Source B.
6. **Chronological Baseline:** Keep the current Experiment 6 chronological result (74.00%) as the main *within-source* baseline for comparison.
