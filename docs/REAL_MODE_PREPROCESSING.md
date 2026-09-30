# Real Mode Preprocessing

## Issue Description
Previously, the frontend Real Mode used an incorrect preprocessing pipeline when performing inference with the `packet_compact_model.pth` checkpoint. The legacy pipeline extracted up to 4096 bytes from the PCAP file and mapped it into a 64x64 grayscale image. This preprocessing method was mismatched with the `packet_compact_model.pth` training representation, causing the model to perform poorly with an accuracy of roughly 34.22%.

## Old Incorrect Pipeline
- **Representation:** 4096 bytes → 64x64 grayscale
- **Extraction:** Reads up to 4096 bytes of raw stream data.
- **Consequence:** The spatial features learned by the model during training (which relied on 20x20 structure) were destroyed, drastically degrading predictive accuracy.

## New Correct Pipeline
To ensure inference matches the exact representation used during training, a dedicated packet-compact inference path (`predict_packet_compact_bytes`) was introduced.
- **Checkpoint:** `ml/checkpoints/packet_compact_model.pth`
- **Representation:** 400-byte maximum packet representation → 20x20 grayscale (one packet per image).
- **Extraction:** Extracts exactly one single packet (maximum 400 bytes). If the packet is shorter than 400 bytes, it is padded with zeros.
- **Normalization:** The exact training normalization is applied using `transforms.Normalize((0.5,), (0.5,))`.

## Test Results
1. **Offline Evaluation**
   The offline model evaluation on the `data/processed_packet_compact` test set remains unchanged at **74.00%**, confirming that the checkpoint is structurally sound and unaffected by frontend code.

2. **Real Mode Inference**
   Real Mode was tested with representative raw PCAP slices:
   - **Benign:** Predicted `benign` (Confidence: 99.9%)
   - **Botnet:** Predicted `botnet` (Confidence: 73.9%)
   - **DDoS:** Predicted `ddos` (Confidence: 100.0%)
   
   The telemetry correctly reports **400 bytes fingerprinted**, verifying that the 20x20 (400-byte) representation is successfully passed to the model in Real Mode without triggering the old 64x64 pipeline.
