"""Batched flow analysis; no image encoding in the inference path."""
import os
import hashlib
import io
import json
import time
from functools import lru_cache
from pathlib import Path
import numpy as np
import torch
from data_processing.production import REPRESENTATION, burst_array, flow_bursts, read_capture
from ml.production_model import FlowResNet, probabilities
from classification.tensor import normalize_batch
from classification.timeline import packet_timeline

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ["benign", "botnet", "ddos"]
torch.set_num_threads(max(1, int(os.getenv("TORCH_THREADS", "2"))))


class FlowClassifier:
    def __init__(self):
        self.path = Path(os.getenv("TRAFFICSCAN_CHECKPOINT", str(ROOT / "ml/checkpoints/flow_resnet.pth")))
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.temperature, self.confidence_threshold, self.entropy_threshold = 1., .75, .8
        self.report, self.error, self.backend, self.calibrated = {}, None, "pytorch", False
        self.checkpoint_sha256 = None
        self.runtime_report = None
        self.require_ready = os.getenv("TRAFFICSCAN_REQUIRE_READY", "0") == "1"
        try:
            if self.path.exists():
                payload = self.path.read_bytes()
                self.checkpoint_sha256 = hashlib.sha256(payload).hexdigest()
                checkpoint = torch.load(io.BytesIO(payload), map_location="cpu", weights_only=True)
                if checkpoint.get("representation") != REPRESENTATION or checkpoint.get("architecture") != "flow_resnet18_1d" or checkpoint.get("classes") != CLASSES:
                    raise ValueError("Incompatible model metadata")
                self.model = FlowResNet().to(self.device)
                self.model.load_state_dict(checkpoint["model_state_dict"])
                self.model.eval()
                self.temperature = float(checkpoint["temperature"])
                if not .05 <= self.temperature <= 100:
                    raise ValueError("Invalid calibration temperature")
                self.confidence_threshold = float(checkpoint.get("confidence_threshold", .75))
                self.entropy_threshold = float(checkpoint.get("entropy_threshold", .8))
                self.report = checkpoint.get("report", {})
                self.calibrated = bool(self.report.get("calibration_valid", False))
                onnx_path = os.getenv("TRAFFICSCAN_ONNX")
                if onnx_path:
                    import onnxruntime as ort
                    options = ort.SessionOptions()
                    options.intra_op_num_threads = max(1, int(os.getenv("TORCH_THREADS", "2")))
                    options.inter_op_num_threads = 1
                    self.session = ort.InferenceSession(onnx_path, sess_options=options, providers=["CPUExecutionProvider"])
                    if self.session.get_modelmeta().custom_metadata_map.get("representation") != REPRESENTATION:
                        raise ValueError("Incompatible ONNX representation")
                    if self.session.get_modelmeta().custom_metadata_map.get("checkpoint_sha256") != self.checkpoint_sha256:
                        raise ValueError("ONNX weights do not match calibrated checkpoint")
                    runtime_metadata = self.session.get_modelmeta().custom_metadata_map
                    self.temperature = float(runtime_metadata.get("temperature", self.temperature))
                    self.calibrated = self.calibrated and runtime_metadata.get("calibration_valid") == "true"
                    self.backend = "onnxruntime"
                    self.device = torch.device("cpu")
                if os.getenv("TRAFFICSCAN_TENSORRT"):
                    if torch.cuda.is_available():
                        from classification.tensorrt_backend import TensorRTBackend
                        backend = TensorRTBackend
                    else:
                        from classification.tensorrt_cuda_backend import TensorRTCudaBackend
                        backend = TensorRTCudaBackend
                    self.trt = backend(os.environ["TRAFFICSCAN_TENSORRT"], self.path, self.checkpoint_sha256)
                    self.temperature = float(self.trt.metadata["temperature"])
                    self.calibrated = self.calibrated and self.trt.metadata.get("calibration_valid") == "true"
                    self.backend = "tensorrt"
                    self.device = torch.device("cpu" if getattr(self.trt, "cpu_staging", False) else "cuda")
                    engine_path = Path(os.environ["TRAFFICSCAN_TENSORRT"])
                    audit_path = engine_path.with_name(engine_path.name + ".audit.json")
                    if audit_path.exists():
                        audit = json.loads(audit_path.read_text())
                        evidence = audit.get("engine_metadata", {})
                        if (audit.get("checkpoint_sha256") != self.checkpoint_sha256
                                or evidence.get("engine_sha256") != self.trt.metadata["engine_sha256"]
                                or float(evidence.get("temperature", 0)) != self.temperature):
                            raise ValueError("Runtime audit does not match the active engine and calibration")
                        self.runtime_report = audit
        except Exception as error:
            self.model, self.error = None, str(error)

    def health(self):
        execution_device = "cuda (CPU staging)" if self.backend == "tensorrt" and getattr(self.trt, "cpu_staging", False) else str(self.device)
        gates = dict(self.report.get("gates", {}))
        if self.runtime_report:
            measured = self.runtime_report
            gates.update(accuracy=measured["accuracy"] > .95 and measured["packet_weighted_accuracy"] > .95,
                         macro_f1=measured["macro_f1"] > .94, benign_fpr=measured["benign_packet_escalation_rate"] < .001,
                         calibration_reliability=self.calibrated and measured["expected_calibration_error"] < .05,
                         model_batch_latency=measured["timings"]["tensorrt"]["batch64_p95_ms"] < 5,
                         runtime_parity=measured["agreement_with_float32"] >= .99)
        ready = bool(self.model and self.calibrated and gates and all(gates.values()) and (self.backend == "pytorch" or self.runtime_report))
        return dict(status="online" if self.model else "degraded", model="Flow ResNet-18 · 1D", device=execution_device,
                    checkpoint=self.path.name, checkpoint_sha256=self.checkpoint_sha256, classes=CLASSES, representation=REPRESENTATION, backend=self.backend,
                    verdict_policy="release_gated" if self.require_ready else "experimental",
                    temperature_fitted=bool(self.model and self.calibrated),
                    calibrated=bool(self.model and self.calibrated and self.report.get("calibration_validated", False)),
                    production_ready=ready, runtime_report=self.runtime_report,
                    error=self.error or (None if self.model else "Trained flow checkpoint unavailable. Analysis returns UNKNOWN."), report={**self.report, "gates": gates})

    def analyze(self, source, filename, allow_truncated=False):
        start = time.perf_counter()
        packet_count, total_bytes, first, last = 0, 0, None, None
        protocols = {}
        activity = []
        packet_rows = []
        def log_packet(packet, stamp, raw, linktype):
            # Compact rows retain every observed frame, including unsupported
            # packets and packets beyond the first 16 used by the classifier.
            packet_rows.append([packet_count, stamp, len(raw),
                                packet.source if packet else None, packet.sport if packet else None,
                                packet.destination if packet else None, packet.dport if packet else None,
                                {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(packet.protocol, str(packet.protocol)) if packet else "Unsupported",
                                linktype])
        def records():
            nonlocal packet_count, total_bytes, first, last
            for stamp, raw, linktype in read_capture(source, max_packets=100001, allow_truncated=allow_truncated):
                packet_count += 1
                if packet_count > 100000:
                    raise ValueError("Capture exceeds 100,000 packet limit; split the capture")
                total_bytes += len(raw)
                activity.append((stamp, len(raw)))
                first = stamp if first is None else min(first, stamp)
                last = stamp if last is None else max(last, stamp)
                yield stamp, raw, linktype
        results, pending, pending_packets, pending_ready = [], [], [], []
        model_ms = 0.
        def flush():
            nonlocal model_ms
            if not pending:
                return
            began = time.perf_counter()
            arrays = np.stack(pending)
            probs, entropies, rejected = np.zeros((len(pending), 3)), np.ones(len(pending)), np.ones(len(pending), dtype=bool)
            if self.model:
                tensor = normalize_batch(arrays, self.device)
                with torch.inference_mode():
                    if self.backend == "onnxruntime":
                        logits = torch.from_numpy(self.session.run(None, {self.session.get_inputs()[0].name: tensor.cpu().numpy()})[0])
                    elif self.backend == "tensorrt":
                        logits = self.trt(tensor)
                    else:
                        logits = self.model(tensor)
                    p, e, r = probabilities(logits, self.temperature, self.confidence_threshold, self.entropy_threshold)
                    probs, entropies, rejected = p.cpu().numpy(), e.cpu().numpy(), r.cpu().numpy()
                    if not self.calibrated:
                        rejected[:] = True
                    if self.require_ready and not self.health()["production_ready"]:
                        rejected[:] = True
            model_ms += (time.perf_counter() - began) * 1000
            for index, packets in enumerate(pending_packets):
                packet = packets[0]
                protocol = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(packet.protocol, str(packet.protocol))
                protocols[protocol] = protocols.get(protocol, 0) + len(packets)
                prediction = "unknown" if rejected[index] else CLASSES[int(probs[index].argmax())]
                results.append(dict(id=len(results) + 1, prediction=prediction, confidence=float(probs[index].max()),
                                    suggested_class=CLASSES[int(probs[index].argmax())] if self.model else None,
                                    probabilities={name: float(probs[index][i]) for i, name in enumerate(CLASSES)},
                                    entropy=float(entropies[index]), source=packet.source, destination=packet.destination,
                                    sport=packet.sport, dport=packet.dport, protocol=protocol, packets=len(packets),
                                    bytes=sum(len(p.raw) for p in packets), timestamp=packet.timestamp,
                                    ready_timestamp=pending_ready[index],
                                    packet_timeline=[[p.timestamp, len(p.raw)] for p in packets],
                                    fingerprint=arrays[index].flatten().tolist(),
                                    hex_dump=[" ".join(f"{v:02x}" for v in row) for row in arrays[index][:4]]))
            pending.clear()
            pending_packets.clear()
            pending_ready.clear()
        for packets in flow_bursts(records(), on_packet=log_packet):
            if len(results) + len(pending) >= 4096:
                raise ValueError("Capture exceeds 4,096 flow-burst limit; split the capture")
            pending.append(burst_array(packets))
            pending_packets.append(packets)
            # Partial bursts become usable on idle/eviction/capture-end, not
            # retroactively at the arrival of their last represented packet.
            pending_ready.append(max(last or packets[-1].timestamp, max(p.timestamp for p in packets)))
            if len(pending) == 64:
                flush()
        flush()
        if not results:
            raise ValueError("Capture contains no supported IP flows")
        counts = {name: sum(r["prediction"] == name for r in results) for name in [*CLASSES, "unknown"]}
        prediction = next((name for name in ["ddos", "botnet", "unknown", "benign"] if counts[name]), "unknown")
        elapsed = (time.perf_counter() - start) * 1000
        return dict(filename=filename, prediction=prediction, model_available=bool(self.model), calibrated=self.health()["calibrated"],
                    representation=REPRESENTATION, counts=counts, flows=results, timeline=packet_timeline(activity),
                    packet_log=dict(version=1, columns=["sequence", "timestamp", "bytes", "source", "sport", "destination", "dport", "protocol", "linktype"],
                                    rows=packet_rows, scope="Every recorded frame; packet receipt is separate from flow-level prediction"),
                    telemetry=dict(packet_count=packet_count, flow_count=len(results), total_bytes=total_bytes,
                                   duration_seconds=(last - first) if first is not None else 0, protocols=protocols,
                                   analysis_ms=round(elapsed, 2), model_ms=round(model_ms, 2), packets_per_second=round(packet_count / max(elapsed / 1000, 1e-9))),
                    coverage=dict(analyzed_ip_packets=sum(r["packets"] for r in results), total_packets=packet_count), model=self.health())


@lru_cache(maxsize=1)
def get_flow_classifier():
    return FlowClassifier()
