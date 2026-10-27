"""Export calibrated flow model and optionally quantize with real calibration data."""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from data_processing.production import REPRESENTATION
from ml.production_model import FlowResNet, calibrate_temperature


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", default="ml/checkpoints/flow_resnet.pth")
    parser.add_argument("--output", default="ml/checkpoints/flow_resnet.onnx")
    parser.add_argument("--int8", action="store_true")
    parser.add_argument("--symmetric", action="store_true", help="Use zero-point-zero QDQ for TensorRT compatibility")
    parser.add_argument("--data", default="data/production/dataset.npz")
    args = parser.parse_args()
    import onnx
    import onnxruntime as ort
    checkpoint = torch.load(args.checkpoint, map_location="cpu", weights_only=True)
    if checkpoint["representation"] != REPRESENTATION:
        raise ValueError("Incompatible representation")
    model = FlowResNet().eval()
    model.load_state_dict(checkpoint["model_state_dict"])
    probe = torch.rand(64, 1, 512) * 2 - 1
    torch.onnx.export(model, probe, args.output, input_names=["bytes"], output_names=["logits"],
                      dynamic_axes={"bytes": {0: "batch"}, "logits": {0: "batch"}}, opset_version=17, dynamo=False)
    graph = onnx.load(args.output)
    base_metadata = {"representation": REPRESENTATION, "temperature": str(checkpoint["temperature"]),
                    "calibration_valid": str(checkpoint.get("report", {}).get("calibration_valid", False)).lower(), "precision": "float32",
                    "checkpoint_sha256": hashlib.sha256(Path(args.checkpoint).read_bytes()).hexdigest()}
    onnx.helper.set_model_props(graph, base_metadata)
    onnx.checker.check_model(graph)
    onnx.save(graph, args.output)
    session = ort.InferenceSession(args.output, providers=["CPUExecutionProvider"])
    with torch.inference_mode():
        expected = model(probe).numpy()
    actual = session.run(None, {"bytes": probe.numpy()})[0]
    np.testing.assert_allclose(actual, expected, rtol=1e-4, atol=1e-5)
    report = dict(onnx=args.output, max_absolute_error=float(abs(actual - expected).max()), torch_onnx_parity=True)
    if args.int8:
        from onnxruntime.quantization import CalibrationDataReader, QuantFormat, QuantType, quantize_static
        from onnxruntime.quantization.shape_inference import quant_pre_process
        data = np.load(args.data, allow_pickle=False)
        if str(data["representation"]) != REPRESENTATION:
            raise ValueError("Calibration representation mismatch")
        arrays = data["x"][data["split"] == "validation"].astype(np.float32).reshape(-1, 1, 512) / 127.5 - 1
        if not len(arrays):
            raise ValueError("No held-out calibration samples")
        class Reader(CalibrationDataReader):
            def __init__(self):
                self.batches = iter([{ "bytes": arrays[i:i + 64]} for i in range(0, min(len(arrays), 4096), 64)])
            def get_next(self):
                return next(self.batches, None)
        quantized = str(Path(args.output).with_suffix(".int8.onnx"))
        prepared = str(Path(args.output).with_suffix(".prepared.onnx"))
        quant_pre_process(args.output, prepared)
        quantize_static(prepared, quantized, Reader(), quant_format=QuantFormat.QDQ,
                        activation_type=QuantType.QInt8, weight_type=QuantType.QInt8, per_channel=True,
                        extra_options={"ActivationSymmetric": True, "WeightSymmetric": True, "QuantizeBias": False} if args.symmetric else {})
        runtime = ort.InferenceSession(quantized, providers=["CPUExecutionProvider"])
        reference = session.run(None, {"bytes": arrays[:64]})[0]
        output = runtime.run(None, {"bytes": arrays[:64]})[0]
        report.update(int8=quantized, validation_prediction_agreement=float((reference.argmax(1) == output.argmax(1)).mean()),
                      int8_max_logit_error=float(abs(reference - output).max()), requires_independent_int8_audit=True)
        validation_logits = np.concatenate([runtime.run(None, {"bytes": arrays[i:i + 64]})[0] for i in range(0, len(arrays), 64)])
        validation_labels = torch.from_numpy(data["y"][data["split"] == "validation"].copy()).long()
        int8_temperature = calibrate_temperature(torch.from_numpy(validation_logits), validation_labels)
        quantized_graph = onnx.load(quantized)
        existing_metadata = {value.key: value.value for value in quantized_graph.metadata_props}
        onnx.helper.set_model_props(quantized_graph, {**existing_metadata, **base_metadata, "precision": "int8_qdq", "temperature": str(int8_temperature),
                                                    "bias_precision": "float32" if args.symmetric else "int32_scaled"})
        onnx.save(quantized_graph, quantized)
        report["int8_temperature"] = int8_temperature
        report["symmetric_quantization"] = args.symmetric
    Path(args.output).with_suffix(".export.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
