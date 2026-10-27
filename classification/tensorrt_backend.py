"""TensorRT 10 execution using Torch-owned CUDA buffers and stream."""
import hashlib
import json
from pathlib import Path
import torch
from data_processing.production import REPRESENTATION


class TensorRTBackend:
    def __init__(self, path, checkpoint, expected_checkpoint_hash=None):
        import tensorrt as trt
        if not torch.cuda.is_available():
            raise RuntimeError("TensorRT requires CUDA")
        path = Path(path)
        metadata = json.loads(path.with_suffix(".json").read_text())
        self.metadata = metadata
        checkpoint_hash = expected_checkpoint_hash or hashlib.sha256(Path(checkpoint).read_bytes()).hexdigest()
        if metadata.get("representation") != REPRESENTATION or metadata.get("checkpoint_sha256") != checkpoint_hash:
            raise ValueError("TensorRT/checkpoint metadata mismatch")
        serialized = path.read_bytes()
        if metadata.get("engine_sha256") != hashlib.sha256(serialized).hexdigest():
            raise ValueError("TensorRT engine integrity mismatch")
        self.logger = trt.Logger(trt.Logger.WARNING)
        self.runtime = trt.Runtime(self.logger)
        self.engine = self.runtime.deserialize_cuda_engine(serialized)
        if self.engine is None:
            raise RuntimeError("Cannot load engine on this NVIDIA host")
        self.context = self.engine.create_execution_context()
        if self.context is None:
            raise RuntimeError("Cannot create TensorRT execution context")

    def __call__(self, tensor):
        x = tensor.contiguous()
        if x.dtype != torch.float32 or not x.is_cuda or x.ndim != 3 or tuple(x.shape[1:]) != (1, 512) or not 1 <= len(x) <= 64:
            raise ValueError("Expected float32 batch of 1–64 flow tensors")
        if not self.context.set_input_shape("bytes", tuple(x.shape)):
            raise ValueError("TensorRT rejected input shape")
        output = torch.empty((len(x), 3), dtype=torch.float32, device=x.device)
        self.context.set_tensor_address("bytes", x.data_ptr())
        self.context.set_tensor_address("logits", output.data_ptr())
        if not self.context.execute_async_v3(torch.cuda.current_stream().cuda_stream):
            raise RuntimeError("TensorRT execution failed")
        return output
