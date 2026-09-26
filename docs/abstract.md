# Abstract — PCAP-to-Image Malware Fingerprinting

**Syllabus mapping:** Unit V (Network Security), Unit II (Data Link framing).

## Real-world problem

Attackers constantly rewrite malware signatures to bypass rule-based firewalls. Signature-only defenses struggle to keep up with polymorphic and novel traffic patterns.

## Approach

Treat network traffic analysis as a **computer vision** problem:

1. Capture raw network frames (binary byte sequences).
2. Convert those sequences into **2D grayscale arrays (images)** — data-link framing as a spatial representation.
3. Train a **Convolutional Neural Network (CNN)** (TensorFlow or PyTorch) to distinguish **benign** traffic from **DDoS** or **Botnet** activity.

## Goal

A visual security pipeline that “looks” at network traffic images to fingerprint malicious patterns beyond brittle, rule-based signatures.
