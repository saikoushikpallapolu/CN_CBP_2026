# Local GPU execution

This PC has an RTX 4060 Laptop GPU with 8 GB VRAM. CUDA training works in `.venv-gpu`. Native Windows TensorRT bindings are blocked by Application Control; that protection remains enabled. The verified alternative is Linux Docker with NVIDIA GPU access and CUDA Python pinned staging buffers.

The target-specific Linux libraries are unmodified NVIDIA binaries. Acquisition verifies ZIP CRC and each file's SHA-256 against NVIDIA's wheel RECORD. The package includes the requested GPU's builder resource; it intentionally excludes other GPU architectures. Their original license is retained beside the libraries. This avoids downloading the 3.8 GB bundle for every supported GPU.

```powershell
# Training on Windows, using the existing isolated CUDA environment
.venv-gpu/Scripts/python.exe -m ml.train_production --device cuda

# Build the Linux CPU base, then acquire and build the GPU runtime
docker build --target production -f deploy/Dockerfile -t trafficscan:production .
python -m scripts.acquire_tensorrt_linux --sm 89
python -m scripts.gpu_container image

# Export symmetric INT8 with floating-point biases for TensorRT 11
python -m ml.export_production --output ml/checkpoints/flow_resnet.trt.onnx --int8 --symmetric
python -m scripts.gpu_container compile
python -m scripts.gpu_container audit
python -m scripts.gpu_container benchmark
python -m scripts.gpu_container stability
```

The audit fits the engine's temperature on validation logits before evaluating test data. It reports agreement, accuracy, F1, represented-packet escalation, calibration error and synchronized timings. The CUDA Python timing includes pinned-host copies and host/device transfers. It excludes capture parsing, HTTP handling and waiting for the first 16 packets of a flow. The capture benchmark measures the separate offline pipeline.

Engine metadata uses `.engine.json`, and its matched runtime audit uses `.engine.audit.json`; the training report remains the separate `.json` file. Start the localhost review product with `python -m scripts.review_app start`. See [the current review report](FINAL_REVIEW_REPORT.md).

To select the candidate artifacts, add `--model candidate_flow_resnet --data data/production/candidate_dataset.npz` to compile/audit/benchmark commands. Engine metadata must match the checkpoint hash. GPU engines are not portable across arbitrary TensorRT versions, platforms or GPU architectures. A T4 requires `--sm 75` libraries and an engine rebuilt on that T4; use a CUDA/TensorRT release compatible with its installed driver.

The default web service remains experimental while calibration, benign escalation, macro F1 and operational gates fail. Deployment compose uses `TRAFFICSCAN_REQUIRE_READY=1`, forcing UNKNOWN on failed release gates. GPU acceleration does not waive these gates. A 24-hour public replay requires the PC and Docker engine to remain running; it cannot establish campus false-positive rates.

References: [NVIDIA TensorRT installation](https://docs.nvidia.com/deeplearning/tensorrt/latest/installing-tensorrt/install-pip.html), [support matrix](https://docs.nvidia.com/deeplearning/tensorrt/latest/getting-started/support-matrix.html), [CUDA Python installation](https://nvidia.github.io/cuda-python/cuda-bindings/latest/install.html).
