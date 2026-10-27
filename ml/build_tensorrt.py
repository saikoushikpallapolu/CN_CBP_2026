"""Compile a verified ONNX graph on the target NVIDIA host (TensorRT 10+)."""
import argparse
import hashlib
import json
from pathlib import Path
from data_processing.production import REPRESENTATION
from classification.artifacts import engine_metadata_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("onnx")
    parser.add_argument("--output", default="ml/checkpoints/flow_resnet.engine")
    parser.add_argument("--int8", action="store_true")
    args = parser.parse_args()
    import onnx
    import torch
    import numpy as np
    if torch.cuda.is_available():
        torch.cuda.init()
        gpu = torch.cuda.get_device_name()
        capability = list(torch.cuda.get_device_capability())
    else:
        from cuda.bindings import runtime as cudart
        from classification.tensorrt_cuda_backend import checked
        checked(cudart.cudaSetDevice(0))
        properties = checked(cudart.cudaGetDeviceProperties(0))
        gpu = properties.name.decode().rstrip("\x00")
        capability = [properties.major, properties.minor]
    import tensorrt as trt
    graph = onnx.load(args.onnx)
    metadata = {entry.key: entry.value for entry in graph.metadata_props}
    if metadata.get("representation") != REPRESENTATION:
        raise ValueError("Incompatible representation")
    if args.int8 and not any(node.op_type == "QuantizeLinear" for node in graph.graph.node):
        raise ValueError("INT8 requires a calibrated QDQ graph from ml.export_production --int8")
    if args.int8:
        constants = {value.name: onnx.numpy_helper.to_array(value) for value in graph.graph.initializer}
        for node in graph.graph.node:
            if node.op_type in ("QuantizeLinear", "DequantizeLinear") and len(node.input) > 2:
                if node.input[2] in constants and np.any(constants[node.input[2]] != 0):
                    raise ValueError("TensorRT requires symmetric QDQ: export with --symmetric")
    logger = trt.Logger(trt.Logger.WARNING)
    builder = trt.Builder(logger)
    major = int(trt.__version__.split(".")[0])
    flags = 0
    if major < 11:
        flags = 1 << int(trt.NetworkDefinitionCreationFlag.EXPLICIT_BATCH)
        flags |= 1 << int(trt.NetworkDefinitionCreationFlag.STRONGLY_TYPED)
    network = builder.create_network(flags)
    parser = trt.OnnxParser(network, logger)
    if not parser.parse(Path(args.onnx).read_bytes()):
        raise RuntimeError("\n".join(str(parser.get_error(i)) for i in range(parser.num_errors)))
    config = builder.create_builder_config()
    config.set_memory_pool_limit(trt.MemoryPoolType.WORKSPACE, 1 << 30)
    # Precision is declared by Q/DQ in the graph. TensorRT 11 removed weak
    # typing precision flags; a strongly typed network also works on 10.x.
    profile = builder.create_optimization_profile()
    profile.set_shape("bytes", (1, 1, 512), (64, 1, 512), (64, 1, 512))
    config.add_optimization_profile(profile)
    serialized = builder.build_serialized_network(network, config)
    if serialized is None:
        raise RuntimeError("TensorRT engine compilation failed")
    destination = Path(args.output)
    destination.write_bytes(bytes(serialized))
    engine_metadata_path(destination).write_text(json.dumps({**metadata, "engine_sha256": hashlib.sha256(bytes(serialized)).hexdigest(),
                                                            "precision": "int8_qdq" if args.int8 else "float32", "target_runtime": trt.__version__,
                                                            "gpu": gpu, "compute_capability": capability}, indent=2))
    print(destination)


if __name__ == "__main__":
    main()
