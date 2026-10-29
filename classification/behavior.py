"""Causal behavioral context. Addresses identify counters, never model features."""
from collections import Counter, OrderedDict, deque
import json
import math
from pathlib import Path
import numpy as np

VERSION = "flow-behavior-v1"
FEATURES = ["log_packets", "log_bytes", "log_duration", "log_length_mean", "log_length_std",
            "log_iat_mean", "log_iat_std", "forward_fraction", "syn_fraction", "ack_fraction", "rst_fraction",
            "log_destination_packets_1s", "log_destination_bytes_1s", "log_destination_flows_1s",
            "log_destination_senders_1s", "tcp", "udp", "other"]


class BehaviorContext:
    def __init__(self):
        self.flows = OrderedDict()
        self.window = deque()
        self.destinations = {}
        self.watermark = -math.inf

    def observe(self, packet, stamp, raw, linktype):
        if packet is None:
            return
        self.watermark = max(self.watermark, stamp)
        while self.window and (self.window[0][0] < self.watermark - 1 or len(self.window) >= 100000):
            _, destination, key, source, size = self.window.popleft()
            bucket = self.destinations[destination]
            bucket[0] -= 1; bucket[1] -= size
            for counts, value in ((bucket[2], key), (bucket[3], source)):
                counts[value] -= 1
                if not counts[value]: del counts[value]
            if not bucket[0]: del self.destinations[destination]
        # Out-of-order frames remain in local flow context, but cannot extend
        # the rolling window backwards and leak later context into earlier time.
        if stamp >= self.watermark - 1:
            bucket = self.destinations.setdefault(packet.destination, [0, 0, Counter(), Counter()])
            bucket[0] += 1; bucket[1] += len(raw)
            bucket[2][packet.key] += 1; bucket[3][packet.source] += 1
            self.window.append((self.watermark, packet.destination, packet.key, packet.source, len(raw)))
        flags = raw[packet.transport_offset + 13] if packet.protocol == 6 else 0
        history = self.flows.pop(packet.key, deque(maxlen=128))
        if history and (stamp - history[-1][0] > 30 or flags & 0x12 == 2):
            history.clear()
        history.append((stamp, len(raw), packet.source, flags))
        self.flows[packet.key] = history
        if len(self.flows) > 8192: self.flows.popitem(last=False)

    def features(self, packet):
        rows = list(self.flows.get(packet.key, [(packet.timestamp, len(packet.raw), packet.source, 0)]))
        times = np.array([r[0] for r in rows]); lengths = np.array([r[1] for r in rows])
        iat = np.maximum(0, np.diff(times))
        bucket = self.destinations.get(packet.destination, [0, 0, {}, {}])
        logged = [len(rows), float(lengths.sum()), max(0, float(times.max() - times.min())),
                  float(lengths.mean()), float(lengths.std()), float(iat.mean()) if len(iat) else 0,
                  float(iat.std()) if len(iat) else 0]
        ratios = [sum(r[2] == packet.source for r in rows) / len(rows)]
        ratios += [sum(bool(r[3] & flag) for r in rows) / len(rows) for flag in (2, 16, 4)]
        return np.array([math.log1p(v) for v in logged] + ratios +
                        [math.log1p(v) for v in (bucket[0], bucket[1], len(bucket[2]), len(bucket[3]))] +
                        [float(packet.protocol == 6), float(packet.protocol == 17), float(packet.protocol not in (6, 17))], dtype=np.float32)


def tree_values(trees, x):
    """Evaluate explicit JSON trees; model loading never deserializes pickle."""
    outputs = []
    x = np.asarray(x, dtype=np.float32)
    for tree in trees:
        nodes = np.zeros(len(x), dtype=int)
        left, right = np.asarray(tree["left"]), np.asarray(tree["right"])
        feature, threshold = np.asarray(tree["feature"]), np.asarray(tree["threshold"])
        for _ in range(64):
            active = left[nodes] >= 0
            if not active.any(): break
            selected = nodes[active]
            nodes[active] = np.where(x[active, feature[selected]] <= threshold[selected], left[selected], right[selected])
        else: raise ValueError("Behavior tree exceeds supported depth")
        outputs.append(np.asarray(tree["value"])[nodes])
    return np.mean(outputs, axis=0)


class BehaviorDetector:
    def __init__(self, path):
        self.artifact = None; self.error = None
        try:
            path = Path(path)
            if path.exists():
                artifact = json.loads(path.read_text())
                if artifact["representation"] != VERSION or artifact["features"] != FEATURES:
                    raise ValueError("Incompatible behavioral representation")
                if not math.isfinite(artifact["anomaly_threshold"]) or not math.isfinite(artifact["isolation_normalizer"]) or artifact["isolation_normalizer"] <= 0:
                    raise ValueError("Invalid anomaly threshold or normalization")
                for model in ("classifier", "isolation"):
                    if not 1 <= len(artifact[model]) <= 256: raise ValueError("Invalid forest size")
                    for tree in artifact[model]:
                        for key in ("left", "right", "feature", "threshold", "value"):
                            tree[key] = np.asarray(tree[key])
                        count = len(tree["left"])
                        if not 1 <= count <= 100000 or any(len(tree[key]) != count for key in ("right", "feature", "threshold", "value")):
                            raise ValueError("Invalid behavior tree dimensions")
                        if not np.isfinite(tree["value"]).all() or not np.isfinite(tree["threshold"]).all():
                            raise ValueError("Nonfinite behavior tree values")
                        if tree["value"].shape != ((count,3) if model == "classifier" else (count,)):
                            raise ValueError("Invalid behavior tree output shape")
                        active = tree["left"] >= 0
                        if (np.any(tree["left"][active] >= count) or np.any(tree["right"][active] < 0) or np.any(tree["right"][active] >= count)
                                or np.any(tree["feature"][active] < 0) or np.any(tree["feature"][active] >= len(FEATURES))):
                            raise ValueError("Invalid behavior tree index")
                self.artifact = artifact
        except (OSError, ValueError, KeyError, TypeError) as error:
            self.error = str(error)

    def health(self):
        return dict(available=self.artifact is not None, representation=VERSION, error=self.error,
                    status="advisory_only" if self.artifact else "unavailable",
                    report=self.artifact.get("report") if self.artifact else None,
                    decision_scope="Separate experimental evidence; never overrides byte-model verdicts or enables real blocking")

    def predict(self, x):
        if not self.artifact: return [dict(available=False, status="unavailable") for _ in x]
        try:
            return self._predict(x)
        except (ValueError, IndexError, TypeError, FloatingPointError) as error:
            # A failed advisory model must not disable the primary classifier.
            self.error = str(error); self.artifact = None
            return [dict(available=False, status="unavailable", error=str(error)) for _ in x]

    def _predict(self, x):
        probabilities = tree_values(self.artifact["classifier"], x)
        depth = tree_values(self.artifact["isolation"], x)
        score = np.power(2., -depth / self.artifact["isolation_normalizer"])
        threshold = self.artifact["anomaly_threshold"]
        return [dict(available=True, status="advisory_only", anomaly_score=float(score[i]),
                     anomaly_threshold=threshold, anomalous=bool(score[i] >= threshold),
                     suggested_class=["benign", "botnet", "ddos"][int(probabilities[i].argmax())],
                     confidence=float(probabilities[i].max()),
                     probabilities=dict(zip(("benign", "botnet", "ddos"), map(float, probabilities[i])))) for i in range(len(x))]
