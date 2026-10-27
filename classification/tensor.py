"""Optional native preprocessing with an equivalent vectorized Torch fallback."""
import torch
try:
    import traffic_native
except ImportError:
    traffic_native = None


def normalize_batch(arrays, device):
    if traffic_native is None:
        return torch.from_numpy(arrays).float().reshape(-1, 1, 512).div_(127.5).sub_(1).to(device)
    output = torch.empty((len(arrays), 1, 512), dtype=torch.float32, pin_memory=device.type == "cuda")
    traffic_native.normalize(memoryview(arrays).cast("B"), memoryview(output.numpy()).cast("B"))
    return output.to(device, non_blocking=device.type == "cuda")
