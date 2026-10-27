"""TensorRT with reusable pinned host buffers through official CUDA Python.

Supports Linux GPU deployments with CPU-only PyTorch for checkpoint handling.
Inference runs on CUDA; host normalization and probability reporting stay on CPU.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from data_processing.production import REPRESENTATION
from classification.artifacts import engine_metadata_path


def checked(result):
    if int(result[0]) != 0:
        raise RuntimeError(f"CUDA operation failed: {result[0]}")
    return result[1] if len(result) == 2 else result[1:] if len(result) > 2 else None


class TensorRTCudaBackend:
    cpu_staging = True

    def __init__(self, path, checkpoint, expected_checkpoint_hash=None):
        import tensorrt as trt
        from cuda.bindings import runtime as cudart
        self.cuda = cudart
        path = Path(path)
        self.metadata = json.loads(engine_metadata_path(path).read_text())
        serialized = path.read_bytes()
        checkpoint_hash = expected_checkpoint_hash or hashlib.sha256(Path(checkpoint).read_bytes()).hexdigest()
        if self.metadata.get("representation") != REPRESENTATION or self.metadata.get("checkpoint_sha256") != checkpoint_hash:
            raise ValueError("TensorRT/checkpoint metadata mismatch")
        if self.metadata.get("engine_sha256") != hashlib.sha256(serialized).hexdigest():
            raise ValueError("TensorRT engine integrity mismatch")
        checked(cudart.cudaSetDevice(0))
        self.logger = trt.Logger(trt.Logger.WARNING)
        self.runtime = trt.Runtime(self.logger)
        self.engine = self.runtime.deserialize_cuda_engine(serialized)
        if self.engine is None:
            raise RuntimeError("Cannot load engine on this NVIDIA host")
        self.context = self.engine.create_execution_context()
        if self.context is None:
            raise RuntimeError("Cannot create TensorRT context")
        self.stream = checked(cudart.cudaStreamCreate())
        self.host_input = checked(cudart.cudaHostAlloc(64 * 512 * 4, 0))
        self.host_output = checked(cudart.cudaHostAlloc(64 * 3 * 4, 0))
        self.device_input = checked(cudart.cudaMalloc(64 * 512 * 4))
        self.device_output = checked(cudart.cudaMalloc(64 * 3 * 4))
        self.input_array = np.ctypeslib.as_array((ctypes.c_float * (64 * 512)).from_address(int(self.host_input))).reshape(64, 1, 512)
        self.output_array = np.ctypeslib.as_array((ctypes.c_float * (64 * 3)).from_address(int(self.host_output))).reshape(64, 3)

    def __call__(self, tensor):
        if tensor.dtype != torch.float32 or tensor.ndim != 3 or tuple(tensor.shape[1:]) != (1, 512) or not 1 <= len(tensor) <= 64:
            raise ValueError("Expected float32 batch of 1–64 flow tensors")
        count = len(tensor)
        self.input_array[:count] = tensor.detach().cpu().numpy()
        if not self.context.set_input_shape("bytes", tuple(tensor.shape)):
            raise ValueError("TensorRT rejected input shape")
        self.context.set_tensor_address("bytes", int(self.device_input))
        self.context.set_tensor_address("logits", int(self.device_output))
        checked(self.cuda.cudaMemcpyAsync(self.device_input, self.host_input, count * 512 * 4,
                self.cuda.cudaMemcpyKind.cudaMemcpyHostToDevice, self.stream))
        if not self.context.execute_async_v3(int(self.stream)):
            raise RuntimeError("TensorRT execution failed")
        checked(self.cuda.cudaMemcpyAsync(self.host_output, self.device_output, count * 3 * 4,
                self.cuda.cudaMemcpyKind.cudaMemcpyDeviceToHost, self.stream))
        checked(self.cuda.cudaStreamSynchronize(self.stream))
        return torch.from_numpy(self.output_array[:count].copy())

    def __del__(self):
        try:
            cuda = self.cuda
            if hasattr(self, "stream"):
                cuda.cudaStreamSynchronize(self.stream)
            for name in ("device_input", "device_output"):
                if hasattr(self, name):
                    cuda.cudaFree(getattr(self, name))
            for name in ("host_input", "host_output"):
                if hasattr(self, name):
                    cuda.cudaFreeHost(getattr(self, name))
            if hasattr(self, "stream"):
                cuda.cudaStreamDestroy(self.stream)
        except Exception:
            pass  # Driver/interpreter may already be shutting down.
