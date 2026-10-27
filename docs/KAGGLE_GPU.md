# Kaggle training

The compact 1D ResNet can train on a Kaggle T4. Select a GPU accelerator in notebook settings. The trainer uses one GPU; two assigned T4s do not automatically combine their memory. Rebuild TensorRT engines on the destination GPU; the RTX 4060 engine is not a portable T4 artifact.

After building the independent-source dataset locally:

```text
python -m scripts.package_kaggle
```

Upload `artifacts/kaggle/trafficscan-training.zip` as a private Kaggle dataset and attach it to a GPU notebook. The bundle includes sanitized tensors, source provenance, identity audit and training code. It excludes raw captures and API credentials. Source holdouts and failed release gates remain enforced.

Run this first notebook cell:

```python
from pathlib import Path
import hashlib, json, os, zipfile
bundles = list(Path('/kaggle/input').rglob('trafficscan-training.zip'))
assert len(bundles) == 1, 'Attach exactly one TrafficScan training bundle'
workspace = Path('/kaggle/working/trafficscan')
workspace.mkdir(exist_ok=True)
with zipfile.ZipFile(bundles[0]) as archive:
    for member in archive.infolist():
        assert (workspace / member.filename).resolve().is_relative_to(workspace.resolve())
    archive.extractall(workspace)
os.chdir(workspace)
expected = json.loads(Path('bundle.json').read_text())['dataset_sha256']
assert hashlib.sha256(Path('data/production/dataset.npz').read_bytes()).hexdigest() == expected
import torch
assert torch.cuda.is_available(), 'Enable a GPU accelerator in notebook settings'
print(torch.cuda.get_device_name(), torch.version.cuda)
```

Train with an explicit CUDA requirement:

```python
import subprocess, sys
subprocess.run([sys.executable, '-m', 'ml.train_production', '--device', 'cuda',
                '--epochs', '30', '--batch-size', '64'], check=True)
```

Read the measured results in `ml/checkpoints/flow_resnet.json`. Download the `.pth` and `.json` artifacts from `/kaggle/working/trafficscan/ml/checkpoints/`. Exporting ONNX additionally requires `onnx` and `onnxruntime`; install them through the notebook package manager if absent. Static INT8 calibration uses only validation data.

Kaggle is suitable for this offline training/evaluation workflow. It does not validate a persistent deployed API, live NIC ingestion or a campus false-positive rate. See the [NVIDIA Kaggle setup guide](https://docs.nvidia.com/datascience/deployment/latest/platforms/kaggle/) and [TensorRT support matrix](https://docs.nvidia.com/deeplearning/tensorrt/latest/getting-started/support-matrix.html).
