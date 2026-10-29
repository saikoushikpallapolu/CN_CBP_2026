import io
import json
import numpy as np
from classification.behavior import BehaviorContext, BehaviorDetector, FEATURES, VERSION
from classification.response import response_policy
from data_processing.production import parse_packet
from tests.test_production import frame


def test_context_is_causal_and_observes_more_than_model_prefix():
    context = BehaviorContext()
    first = None
    for index in range(40):
        raw = frame(flags=16)
        packet = parse_packet(raw, index * .01)
        first = first or packet
        context.observe(packet, packet.timestamp, raw, 1)
        if index == 15: prefix = context.features(first).copy()
    assert round(np.expm1(prefix[0])) == 16
    assert round(np.expm1(context.features(first)[0])) == 40
    # A previously returned feature vector is not mutated by future arrivals.
    assert round(np.expm1(prefix[0])) == 16


def test_context_uses_counts_instead_of_endpoint_identity():
    original, changed = BehaviorContext(), BehaviorContext()
    for index in range(8):
        p = parse_packet(frame(flags=16), index / 100)
        q = parse_packet(frame(source=b"\xc0\xa8\x01\x02", destination=b"\xc0\xa8\x01\x03", sport=60000, flags=16), index / 100)
        original.observe(p,p.timestamp,p.raw,1); changed.observe(q,q.timestamp,q.raw,1)
    assert np.array_equal(original.features(p), changed.features(q))
    later = parse_packet(frame(flags=16), 10.)
    original.observe(later,later.timestamp,later.raw,1)
    assert round(np.expm1(original.features(later)[11])) == 1


def test_uncertain_anomalies_never_become_automatic_blocks():
    flow = dict(prediction="unknown", confidence=.999, entropy=.01, behavior={"anomalous":True}, uncertainty_reason="release_gates_pending")
    policy = response_policy(flow)
    assert policy["simulate"] == "review"
    assert policy["priority"] == "elevated"
    flow.update(prediction="ddos",confidence=.74)
    assert response_policy(flow)["simulate"] == "alert"
    flow["confidence"] = .99
    assert response_policy(flow)["simulate"] == "would_block"
    assert response_policy(flow)["enforcement"] == "simulation_only"
    flow["prediction"] = "benign"
    assert response_policy(flow)["simulate"] == "allow"


def test_missing_or_incompatible_advisory_model_has_no_fabricated_score(tmp_path):
    missing = BehaviorDetector(tmp_path / "missing.json")
    assert not missing.predict([np.zeros(len(FEATURES))])[0]["available"]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"representation":"old", "features":FEATURES}))
    assert BehaviorDetector(bad).health()["error"]
    broken = dict(representation=VERSION, features=FEATURES, anomaly_threshold=.5, isolation_normalizer=1,
                  classifier=[dict(left=[-1],right=[-1],feature=[-2],threshold=[0],value=[[float("nan"),0,1]])])
    broken["isolation"] = broken["classifier"]
    bad.write_text(json.dumps(broken))
    invalid = BehaviorDetector(bad)
    assert invalid.health()["error"]
    assert not invalid.predict([np.zeros(len(FEATURES))])[0]["available"]


def test_analysis_exposes_uncertainty_reason_and_policy_without_changing_verdict(tmp_path, monkeypatch):
    from classification.production import FlowClassifier
    from tests.test_production import pcap
    monkeypatch.setenv("TRAFFICSCAN_CHECKPOINT",str(tmp_path / "missing.pth"))
    monkeypatch.delenv("TRAFFICSCAN_TENSORRT",raising=False)
    result = FlowClassifier().analyze(io.BytesIO(pcap([frame(flags=16)] * 20)), "sample.pcap")
    flow = result["flows"][0]
    assert flow["prediction"] == "unknown"
    assert flow["uncertainty_reason"] == "model_unavailable"
    assert flow["response"]["simulate"] == "review"
    assert len(flow["behavior_features"]) == len(FEATURES)
    assert flow["ready_sequence"] == 16
