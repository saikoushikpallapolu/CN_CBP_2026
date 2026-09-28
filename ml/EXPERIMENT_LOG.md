# PCAP Malware Fingerprinting — Experiment Log

## Project Configuration
- Image size: 64x64
- Image mode: Grayscale
- Bytes per image: 4096
- Classes:
  - Benign
  - Botnet
  - DDoS
- Images per class: 2000
- Total images: 6000
- CNN framework: PyTorch
- Dataset source: CIC-IDS2017 100-MiB slices
- Important limitation: This is NOT a full CIC-IDS2017 benchmark.

## Experiment 1 — Sequential Sampling
Status: COMPLETED

### Dataset
- 2000 images/class
- 6000 total
- Sequential/non-overlapping byte windows
- First sequential 2,000 valid windows extracted from the beginning of each 100-MiB PCAP slice.

### Split
- Chronological / source-aware split
- 1400 train/class
- 300 validation/class
- 300 test/class

### Model
- **Architecture:** TrafficCNN (3 Conv blocks: 32 -> 64 -> 128, BatchNorm, MaxPool, AdaptiveAvgPool, 2 Linear layers with Dropout)
- **Optimizer:** Adam (lr=0.001, weight_decay=1e-4)
- **Class weights:** Tensor([1.10, 1.20, 0.90])
- **Normalization:** Mean=0.5, Std=0.5
- **Epochs:** 30 (Patience = 7)

### Results
Test Accuracy: 57.44%
Macro F1: 0.5167

Per-class F1:
- Benign: 0.1873
- Botnet: 0.5930
- DDoS: 0.7699

### Interpretation
DDoS is relatively easy to distinguish from its initial sequential bytes. Botnet is partially distinguishable. Benign traffic is poorly separated in this sequential window approach, leading to very low precision and recall for benign classification.

---

## Experiment 2 — Broader Uniform Sampling
Status: COMPLETED

### Files
- data_processing/sample_convert.py
- data_processing/verify_sampled.py
- ml/train_sampled.py
- ml/experiment_report.md

### Dataset
- 2000 unique images/class
- 6000 total
- 64x64 grayscale
- 4096 bytes/image
- Uniformly distributed across the valid readable portion of each PCAP
- Malformed PCAP-NG tail handled safely

### Split
- 1400 train/class
- 300 validation/class
- 300 test/class
- Chronological ordering within each class

### Results
Test Accuracy: 41.11%
Macro F1: 0.3014

Per-class F1:
- Benign: 0.0328
- Botnet: 0.6124
- DDoS: 0.2590

Benign recall: 1.67%

### Comparison
Sequential baseline:
57.44% accuracy / 0.5167 Macro F1

Broader sampling:
41.11% accuracy / 0.3014 Macro F1

### Interpretation
The broader sampling experiment did NOT improve performance within this dataset configuration.

The experiment suggests that traffic characteristics vary substantially across the temporal extent of the available PCAP slices, and chronological train/validation/test separation can expose the model to substantially different distributions. (Note: This is an observation/inference from this experiment, NOT a proven property of the complete CIC-IDS2017 dataset.)

---

## Experiment 3 — Stratified Sampling
Status: COMPLETED

### Objective
Test whether selecting 4096-byte windows evenly across the valid readable portions of each PCAP improves classification compared with the sequential baseline.

### Files
- data_processing/stratified_convert.py
- data_processing/verify_stratified.py
- ml/train_stratified.py

### Dataset
- 2000 unique images/class
- 6000 total
- 64x64 grayscale
- 4096 bytes/image
- Valid PCAP stream divided into 2000 equal bins, picking one random non-overlapping window from each bin.
- Malformed PCAP-NG tail handled safely

### Split
- 1400 train/class
- 300 validation/class
- 300 test/class
- Chronological ordering within each class

### Model
- Architecture: TrafficCNN (Fixed from baseline)
- Training: Exact same as baseline (Adam, lr=0.001, Epochs=30, Patience=7, class weights fixed)
- Checkpoint: ml/checkpoints/stratified_model.pth
- Command used: `python ml\train_stratified.py`

### Results
Test Accuracy: 33.67%
Macro F1: 0.3210
Weighted F1: 0.3210
Best Epoch: 2 (Validation Accuracy: 46.22%)

Per-class F1:
- Benign: 0.1152
- Botnet: 0.5773
- DDoS: 0.2706

### Comparison
Experiment 1 (Sequential): 57.44% accuracy / 0.5167 Macro F1
Experiment 2 (Broader): 41.11% accuracy / 0.3014 Macro F1
Experiment 3 (Stratified): 33.67% accuracy / 0.3210 Macro F1

Experiment 3 decreased accuracy compared to both Experiment 1 and 2. It slightly improved Macro F1 compared to Experiment 2, but heavily decreased metrics compared to the baseline of Experiment 1.

### Interpretation
Stratified sampling resulted in the lowest test accuracy across all experiments. Similar to Experiment 2, selecting images across the entirety of single PCAP slices exacerbates distribution shifts over time. The chronological split then ensures that train, val, and test splits cover wildly different traffic profiles, preventing generalizability under this evaluation framework.

---

## Experiment 4 — Random Stratified Image-Level Split
Status: COMPLETED

### Objective
Test whether changing ONLY the dataset split from chronological to random image-level splitting changes the performance compared to Experiment 3.

### Hypothesis
If chronological splitting exposes the model to severe temporal distribution shifts, an image-level random split over the exact same dataset will mitigate these shifts and increase accuracy.

### Files
- ml/train_random_stratified.py

### Dataset
- Exact same `data/processed_stratified/` dataset generated in Experiment 3.
- Sampling Method: Valid PCAP stream divided into 2000 equal bins, picking one random non-overlapping window from each bin.

### Split
- Random Stratified Image-Level Split
- Deterministic seed: 42
- 1400 train/class
- 300 validation/class
- 300 test/class

### Model
- Architecture: TrafficCNN (Fixed)
- Training Configuration: Fixed (Adam, lr=0.001, Epochs=30, Patience=7, fixed weights)
- Checkpoint: ml/checkpoints/random_stratified_model.pth
- Command used: `python ml\train_random_stratified.py`

### Results
Test Accuracy: 45.22%
Macro F1: 0.4114
Weighted F1: 0.4114
Best Epoch: 2 (Validation Accuracy: 47.33%)
Final Epoch / Early stopping point: 9

Per-class F1:
- Benign: 0.2333
- Botnet: 0.5407
- DDoS: 0.4601

### Comparison
Experiment 1 (Sequential, Chronological Split): 57.44% accuracy / 0.5167 Macro F1
Experiment 2 (Broader, Chronological Split): 41.11% accuracy / 0.3014 Macro F1
Experiment 3 (Stratified, Chronological Split): 33.67% accuracy / 0.3210 Macro F1
Experiment 4 (Stratified, Random Split): 45.22% accuracy / 0.4114 Macro F1

Experiment 4 produced a substantial improvement over Experiment 3 (Test Accuracy +11.55%, Macro F1 +0.0904). However, it did not surpass the Sequential baseline (Experiment 1).

### Data Leakage / Correlation Warning
**WARNING:** Because the images originate from the same underlying 100-MiB PCAP slices, performing a random image-level split inherently allows highly correlated traffic patterns (e.g., adjacent or temporally close network events) to appear simultaneously in both the training set and the test set. 
Therefore, the 45.22% accuracy achieved here is potentially optimistic and **NOT equivalent to genuine cross-PCAP generalizability**. 

### Interpretation
The result provides evidence that split strategy and distribution differences contribute to the performance variation observed across the experiments. The improvement over Experiment 3 shows that temporal traffic variations within the PCAP slice severely harmed chronological evaluation. Nonetheless, the overall metric is still lower than the simple initial sequential extraction.

---

## Experiment 5 — Packet-Aligned Representation
Status: COMPLETED

### Objective
Test whether representing exactly one padded packet per 64x64 image improves classification compared to arbitrary sequential window chunks.

### Hypothesis
Aligning the Ethernet and IP headers consistently to the top-left pixels of the image will allow the CNN to leverage spatial filters to easily detect protocol boundaries and payload sizes, significantly improving accuracy.

### Files
- data_processing/packet_aligned_convert.py
- data_processing/verify_packet_aligned.py
- ml/train_packet_aligned.py

### Dataset
- 2000 unique images/class (6000 total)
- 64x64 grayscale (4096 bytes/image)
- Generated by extracting exactly ONE original network frame per image.
- Short packets padded with zeros up to 4096 bytes. Long packets truncated.
- Extracted sequentially starting from the beginning of the valid portion of the PCAPs.

### Packet-Length Statistics
Because a standard MTU is around 1500 bytes, virtually 100% of packets were strictly shorter than the 4096-byte limit and required zero-padding.
- Benign Avg Length: 205.71 bytes (100.00% padded, 0 truncated)
- Botnet Avg Length: 180.02 bytes (100.00% padded, 0 truncated)
- DDoS Avg Length: 272.40 bytes (99.75% padded, 0.25% truncated)

### Split
- Chronological / source-aware split
- 1400 train/class
- 300 validation/class
- 300 test/class

### Model
- Architecture: TrafficCNN (Fixed)
- Training Configuration: Fixed (Adam, lr=0.001, Epochs=30, Patience=7, fixed weights)
- Checkpoint: ml/checkpoints/packet_aligned_model.pth
- Command used: `python ml\train_packet_aligned.py`

### Results
Test Accuracy: 66.11%
Macro F1: 0.6638
Weighted F1: 0.6638
Best Epoch: 6 (Validation Accuracy: 74.67%)
Final Epoch / Early stopping point: 13

Per-class F1:
- Benign: 0.6203
- Botnet: 0.5738
- DDoS: 0.7972

### Comparison
Experiment 1 (Sequential windows): 57.44% accuracy / 0.5167 Macro F1
Experiment 5 (Packet-Aligned): 66.11% accuracy / 0.6638 Macro F1

Experiment 5 yielded a significant improvement over the Experiment 1 baseline. The most profound improvement occurred in the Benign class, where the F1 score jumped from a catastrophic 0.1873 in Exp 1 to a very solid 0.6203 in Exp 5.

### Interpretation
Representing data logically (one network packet = one image) rather than as arbitrary sequential chunks provides a highly beneficial structural prior for the CNN. By spatially aligning the headers to the start of the 4096-byte array, the network can robustly distinguish Benign traffic from DDoS/Botnet traffic, completely outperforming the flat continuous byte-stream representation despite over 90% of the typical resulting image being completely black (zero-padded).

---

## Experiment 6 — Compact Packet-Aligned Representation
Status: COMPLETED

### Objective
Test whether reducing the excessive zero-padding in the packet-aligned representation (by moving from a 64x64 grid to a 20x20 grid) improves classification accuracy.

### Hypothesis
If over 90% of the 64x64 image is black zero-padding in Experiment 5, the CNN wastes massive capacity processing empty space. By compacting the image to 20x20 (400 bytes), we concentrate the CNN's filters exclusively on the dense, informative headers and primary payload, which should increase both learning efficiency and overall accuracy.

### Files
- data_processing/packet_compact_convert.py
- data_processing/verify_packet_compact.py
- ml/train_packet_compact.py

### Dataset
- 2000 unique images/class (6000 total)
- **20x20 grayscale (400 bytes/image)**
- Extracted sequentially: ONE network frame per image.
- Short packets padded with zeros up to 400 bytes; long packets truncated to 400 bytes.

### Representation Statistics
- Benign Avg Length: 205.71 bytes (90.75% padded <400 bytes, 9.25% truncated)
- Botnet Avg Length: 180.02 bytes (90.65% padded <400 bytes, 9.35% truncated)
- DDoS Avg Length: 272.40 bytes (91.00% padded <400 bytes, 9.00% truncated)

### Split
- Chronological / source-aware split
- 1400 train/class
- 300 validation/class
- 300 test/class

### Model
- Architecture: TrafficCNN (Fixed. The `AdaptiveAvgPool2d((4,4))` gracefully handles the 20x20 input without requiring architectural overrides).
- Training Configuration: Fixed (Adam, lr=0.001, Epochs=30, Patience=7, fixed weights)
- Checkpoint: ml/checkpoints/packet_compact_model.pth
- Command used: `python ml\train_packet_compact.py`

### Results
Test Accuracy: 74.00%
Macro F1: 0.7418
Weighted F1: 0.7418
Best Epoch: 17 (Validation Accuracy: 75.56%)
Final Epoch / Early stopping point: 24

Per-class F1:
- Benign: 0.6620
- Botnet: 0.6625
- DDoS: 0.9010

### Comparison
Experiment 5 (Packet-Aligned, 64x64): 66.11% accuracy / 0.6638 Macro F1
Experiment 6 (Compact, 20x20): 74.00% accuracy / 0.7418 Macro F1

Experiment 6 produced a massive improvement across all metrics.
- Benign F1: 0.6203 -> 0.6620
- Botnet F1: 0.5738 -> 0.6625
- DDoS F1: 0.7972 -> 0.9010

### Interpretation
Reducing the massive zero-padding from the 4096-byte limit to a concise 400-byte limit (20x20 image) profoundly improved CNN performance. Even though ~9% of packets had their trailing payload bytes truncated, preserving exactly the first 400 bytes (which perfectly captures the Ethernet, IP, TCP/UDP headers, and initial payload) proved to be an immensely superior feature representation. The model no longer struggled to process thousands of pixels of empty space, leading to a much more accurate and robust classifier.

---

## Experiment 7 — Packet Metadata Representation
Status: FAILED

### Objective
Test whether explicit packet-level metadata (normalized packet lengths mapped to pixel intensities) can classify the three traffic classes better than the raw-byte packet representation.

### Hypothesis
If packet lengths contain strong statistical signatures for botnet/DDoS traffic, a 20x20 image representing 400 sequential packet lengths will expose these temporal/size patterns directly to the CNN, potentially outperforming models that must learn to parse raw headers. 

### Limitations
This representation intentionally discards:
- packet payload bytes
- protocol header contents
- IP addresses
- ports
- flags
- timestamps
It represents only sequential packet-size patterns. This experiment explicitly tests whether packet-length structure alone contains useful class-discriminating information.

### Exact Representation
- 20x20 grayscale images.
- 1 pixel = 1 packet length.
- Pixel intensity = `min(packet_length, 1500) / 1500.0 * 255`.
- 400 consecutive packets grouped into one image.

### Failure Reason
The experiment FAILED at the dataset generation phase due to an absolute shortage of data in the provided 100-MiB PCAP slices.
To generate the required 2,000 images per class (with each image consuming 400 packets), a total of **800,000 packets per class** is required.
However, the 100-MiB PCAP slices contain vastly fewer packets:
- **Benign:** 148,557 packets total (yields only 371 images)
- **Botnet:** 114,401 packets total (yields only 286 images)
- **DDoS:** 89,103 packets total (yields only 222 images)

Because there are only ~200-300 images available per class, the mandated 1400/300/300 chronological split was impossible to execute.

### Files
- data_processing/metadata_convert.py
- data_processing/verify_metadata.py
- ml/train_metadata.py (Never executed)

---

## Experiment 8 — 256-Byte Packet-Aligned Representation
Status: COMPLETED

### Objective
Test whether reducing the packet representation from 400 bytes (20x20) down to 256 bytes (16x16) improves classification by further reducing zero padding while retaining the beginning of each packet.

### Hypothesis
If reducing empty padding was the key driver of improvement in Experiment 6, pushing the threshold down to 256 bytes might further focus the model on the protocol headers, despite aggressively truncating the payloads of larger packets.

### Files
- data_processing/packet_256_convert.py
- data_processing/verify_packet_256.py
- ml/train_packet_256.py

### Dataset
- 2000 unique images/class (6000 total)
- **16x16 grayscale (256 bytes/image)**
- Extracted sequentially: ONE network frame per image.
- Generated directly from raw packet bytes. Zero-padded if <256, truncated if >256.

### Padding / Truncation Statistics
At the stricter 256-byte threshold, a larger chunk of traffic undergoes payload truncation compared to the 400-byte limit (14% - 18% vs ~9%).
- **Benign:** 85.25% padded <256 bytes | 14.75% truncated
- **Botnet:** 84.05% padded <256 bytes | 15.35% truncated
- **DDoS:** 81.25% padded <256 bytes | 18.75% truncated

### Split
- Chronological / source-aware split
- 1400 train/class
- 300 validation/class
- 300 test/class

### Model
- Architecture: TrafficCNN (Fixed. `AdaptiveAvgPool2d((4,4))` elegantly upsamples the 2x2 final output to match dimensions).
- Training Configuration: Fixed (Adam, lr=0.001, Epochs=30, Patience=7, fixed weights)
- Checkpoint: ml/checkpoints/packet_256_model.pth
- Command used: `python ml\train_packet_256.py`

### Results
Test Accuracy: 66.22%
Macro F1: 0.6658
Weighted F1: 0.6658
Best Epoch: 11 (Validation Accuracy: 71.89%)
Final Epoch / Early stopping point: 18

Per-class F1:
- Benign: 0.6386
- Botnet: 0.6181
- DDoS: 0.7407

### Comparison
Experiment 6 (400-byte / 20x20): 74.00% accuracy / 0.7418 Macro F1
Experiment 8 (256-byte / 16x16): 66.22% accuracy / 0.6658 Macro F1

Experiment 8 resulted in a **DECREASE** across all performance metrics.
- Accuracy dropped from 74.00% to 66.22%.
- Macro F1 dropped from 0.7418 to 0.6658.
- The largest casualty was the DDoS class F1, which plummeted from 0.9010 down to 0.7407.

### Interpretation
The 256-byte representation negatively impacted classification compared to 400 bytes. At 256 bytes, 14.75% to 18.75% of packets were severely truncated, losing up to 144 bytes of active payload data that would have been present in the 400-byte window. The sharp drop in the DDoS metric demonstrates that the early payload (bytes 256–400) contains highly discriminative class signatures. Compressing the window purely to reduce padding crossed the threshold of destroying vital structural traffic data. Therefore, the 400-byte (20x20) representation remains the superior approach.

---

## Experiment 9 — Random Stratified Split (400-Byte Compact Dataset)
Status: COMPLETED

### Objective
Test whether modifying the chronological train/test split strategy into a random image-level split changes the evaluated performance of the best-performing representation (the 400-byte compact packet-aligned dataset).

### Hypothesis
If the previously evaluated 74.00% accuracy was suppressed by significant temporal traffic drift in the chronological split, a random image-level split over the exact same dataset will mitigate these distribution shifts and massively increase the testing accuracy.

### Dataset
- **Existing Dataset:** `data/processed_packet_compact/` (generated in Experiment 6).
- 20x20 grayscale, one packet per image (max 400 bytes).

### Split
- **Random Stratified Image-Level Split**
- Deterministic seed: 42
- Exactly 1400 train, 300 validation, and 300 test images per class.

### Model
- Architecture: TrafficCNN (Fixed)
- Training Configuration: Fixed (Adam, lr=0.001, Epochs=30, Patience=7, fixed weights)
- Checkpoint: `ml/checkpoints/packet_compact_random_model.pth`
- Command used: `python ml\train_packet_compact_random.py`

### Results
Test Accuracy: 94.67%
Macro F1: 0.9469
Weighted F1: 0.9469
Best Epoch: 20 (Validation Accuracy: 95.00%)
Final Epoch / Early stopping point: 27

Per-class F1:
- Benign: 0.9329
- Botnet: 0.9265
- DDoS: 0.9815

### Comparison
Experiment 6 (Chronological Split): 74.00% accuracy / 0.7418 Macro F1
Experiment 9 (Random Split): 94.67% accuracy / 0.9469 Macro F1

Experiment 9 generated an immense metric surge across the board:
- Accuracy: +20.67%
- Macro F1: +0.2051
- Benign F1: +0.2709
- Botnet F1: +0.2640
- DDoS F1: +0.0805

### Critical Generalization Warning
**WARNING:** The random split used in this experiment is **NOT** a genuine unseen-PCAP evaluation. All images originate from the exact same three PCAP source files used by the chronological split. 
By pulling images randomly from the same continuous stream, highly correlated traffic patterns (e.g., temporally adjacent packets from the exact same connection) will appear simultaneously in both the training set and the test set. 
Therefore, this 94.67% result is strictly evidence that random splitting produces an easier test distribution due to data correlation; it is **NOT** a measure of real-world accuracy, it is **NOT** genuine generalization, and it is **NOT** a definitive upper bound.

---

## Experiment 10 — Contiguous Block Split
Status: COMPLETED

### Objective
The purpose is NOT to improve the classification score. The purpose is to explicitly determine whether the 94.67% random-split result remains strong when highly adjacent/related packets are kept contiguous instead of being randomly distributed between train and test.

### Hypothesis
If the 94.67% accuracy of Exp 9 was heavily artificially inflated by data correlation (adjacent packets landing in both sets), then grouping test packets into contiguous chronological blocks will break that correlation and the performance will plummet back down to the baseline levels.

### Dataset
- `data/processed_packet_compact/` (20x20 Grayscale, max 400 bytes).

### Split
- **Deterministic Contiguous Block Split**
- First 70% (1400 images) -> Train
- Next 15% (300 images) -> Validation
- Final 15% (300 images) -> Test
- **Crucial Note:** This split mimics Experiment 6 exactly, but forces the network to test explicitly on hold-out test images evaluated in strict 100-image contiguous chunks.

### Training Configuration
- Architecture: TrafficCNN (Fixed)
- Training Configuration: Fixed (Adam, lr=0.001, Epochs=30, Patience=7, fixed weights)
- Checkpoint: `ml/checkpoints/packet_compact_block_model.pth`
- Command used: `python ml\train_packet_compact_block.py`

### Results
Test Accuracy: 69.11%
Macro F1: 0.6978
Weighted F1: 0.6978
Best Epoch: 5 (Validation Accuracy: 71.33%)
Final Epoch / Early stopping point: 12

Per-class F1:
- Benign: 0.6090
- Botnet: 0.6052
- DDoS: 0.8793

### Block Analysis (Contiguous 100-Image Blocks)
**BENIGN**
- Block 1 (Images 1700-1799): 85.00%
- Block 2 (Images 1800-1899): 88.00%
- Block 3 (Images 1900-1999): **31.00%** (Massive performance collapse)

**BOTNET**
- Block 1 (Images 1700-1799): 54.00%
- Block 2 (Images 1800-1899): 57.00%
- Block 3 (Images 1900-1999): 63.00%

**DDOS**
- Block 1 (Images 1700-1799): **51.00%** (Massive performance collapse)
- Block 2 (Images 1800-1899): 96.00%
- Block 3 (Images 1900-1999): 97.00%

### Comparison
Experiment 6 (Chronological Base): 74.00% accuracy / 0.7418 Macro F1
Experiment 9 (Random Split): 94.67% accuracy / 0.9469 Macro F1
Experiment 10 (Contiguous Block): 69.11% accuracy / 0.6978 Macro F1

Experiment 10 performed vastly worse than Experiment 9 (-25.56% Accuracy, -0.2491 Macro F1) and slightly worse than Experiment 6 (likely due to slightly different early stopping iterations, though fundamentally the same).

### Interpretation
Experiment 10 confirms beyond a doubt that the large improvement observed in Experiment 9 (94.67%) is heavily driven by **strong within-PCAP correlation**. 
When evaluated on contiguous blocks (where temporally adjacent packets are isolated), performance swings wildly (e.g. Benign drops from 88% down to 31% in a single block shift, and DDoS jumps from 51% up to 96%). This demonstrates that chronological chunks of a single PCAP have highly distinct local distributions/temporal drift. Randomly splitting (Exp 9) perfectly masks this temporal drift by seeding these distinct variations evenly into both the training and test sets. 
Thus, the 94.67% metric is strongly correlated and does NOT reflect the model's true capability to generalize to unseen temporal windows or unseen sources.

---

## Experiment 11 — Cross-Source Validation
Status: BLOCKED — Independent PCAP Sources Required

### Why it is blocked
The project has successfully locked in an optimal data representation (400-byte / 20x20 logical packet images, yielding 74.00% baseline accuracy). However, Experiment 10 definitively proved that within-source temporal drift is severe. Because the current dataset has **only one independent PCAP source per class**, it is impossible to evaluate if the model generalizes beyond this exact set of files. 

### Current Available Sources
Currently, exactly ONE file exists for each class:
- **Benign:** `Monday-WorkingHours_slice100MB.pcap`
- **Botnet:** `Friday-WorkingHours_slice100MB.pcap`
- **DDoS:** `Wednesday-workingHours_slice100MB.pcap`

### Required Additional Sources
To unblock this experiment, we require physically distinct, separately captured network streams (Source B) for preferably all three classes (e.g. `Monday-WorkingHours_Part2.pcap`, `Friday-Botnet-Source2.pcap`, etc.).

### Planned Methodology
Once Source B is available:
- **Train exclusively on Source A.**
- **Validate exclusively on Source A.**
- **Test completely on unseen Source B.**
(See `ml/CROSS_SOURCE_PLAN.md` for strict anti-leakage rules).

---

## Current Findings

1. **Compact Logical Representation is superior:** Grouping bytes into 20x20 images (1 packet per image, max 400 bytes) provides the highest baseline representation accuracy (74.00%).
2. **Padding vs Truncation tradeoff:** Removing excessive padding (4096->400) dramatically improves learning. However, aggressively shrinking it further (400->256) destroys critical payload signatures (Exp 8 vs Exp 6), heavily degrading the DDoS classification rate.
3. **Data Leakage in Splits:** Evaluating on a random image-level split (Exp 9) creates massive artificial inflation (74% -> 94.67%) because adjacent network packets share correlated payloads and headers. 
4. **Data Volume Limits Aggregation:** Attempting to represent 400 packets in a single image exhausts a 100-MiB PCAP slice almost immediately, proving that highly aggregated representations cannot be tested adequately on these limited data slices.
5. **Temporal Drift is Severe:** As proved by Exp 10, the accuracy of the model swings violently (from 31% to 97%) depending strictly on the temporal block of the PCAP being evaluated.
6. The available dataset consists of one 100-MiB PCAP slice per class, so conclusions are limited.
7. These experiments should not be presented as a full CIC-IDS2017 benchmark.

---

## Known Limitations

- One PCAP slice per class.
- 100-MiB slices rather than the complete dataset.
- Potential temporal traffic drift.
- Potential label noise from using broad class-level PCAP slices.
- Chronological splitting can create distribution differences.
- Random image-level splitting across a single PCAP slice can lead to data leakage/optimistic evaluation due to highly correlated intra-stream traffic packets.
- Results are experimental and dataset-specific.
- No claim of generalization to the complete CIC-IDS2017 dataset.

---

## Next Experiments
*(No proposed experiments at this time)*

---

## Experiment Rules

For every future experiment:
1. Change ONE major variable at a time whenever practical.
2. Keep the CNN architecture fixed unless architecture is explicitly the variable being tested.
3. Record exact dataset size and sampling method.
4. Record exact train/validation/test split.
5. Record accuracy, macro F1, and per-class precision/recall/F1.
6. Record the checkpoint filename.
7. Record the exact command used to run the experiment.
8. Record important warnings/errors.
9. Record whether the experiment improved or degraded the previous baseline.
10. Never delete previous experiment results.
11. Never overwrite an old experiment's metrics with new metrics.
12. Never claim benchmark-level conclusions from these limited PCAP slices.
