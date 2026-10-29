import io
import struct
import pytest
import torch
from fastapi.testclient import TestClient
from data_processing.production import parse_packet, sanitize, packet_features, read_capture, flow_bursts, burst_array
from ml.production_model import FlowResNet, FocalLoss, probabilities, calibrate_temperature


def frame(source=b"\x0a\x00\x00\x01", destination=b"\x0a\x00\x00\x02", sport=55000, flags=2, options=b"", payload=b"hello"):
    ether = b"\xaa" * 12 + b"\x08\x00"
    ip = bytes([0x45 + len(options) // 4, 0]) + struct.pack("!HHHBBH", 40 + len(options) + len(payload), 4321, 0, 64, 6, 1234) + source + destination + options
    tcp = struct.pack("!HHIIBBHHH", sport, 80, 12345, 67890, 0x50, flags, 65535, 123, 0)
    return ether + ip + tcp + payload


def pcap(frames, endian="<"):
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    data = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)
    for i, raw in enumerate(frames):
        data += struct.pack(endian + "IIII", 1500000000 + i, 123, len(raw), len(raw)) + raw
    return data


def block(kind, body, endian):
    return struct.pack(endian + "II", kind, len(body) + 12) + body + struct.pack(endian + "I", len(body) + 12)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_capture_formats(endian):
    raw = frame()
    assert list(read_capture(io.BytesIO(pcap([raw], endian))))[0][1] == raw
    shb = block(0x0a0d0d0a, struct.pack(endian + "IHHq", 0x1a2b3c4d, 1, 0, -1), endian)
    idb = block(1, struct.pack(endian + "HHI", 1, 0, 65535), endian)
    stamp = 1500000000 * 1000000
    epb = block(6, struct.pack(endian + "IIIII", 0, stamp >> 32, stamp & 0xffffffff, len(raw), len(raw)) + raw + bytes((-len(raw)) % 4), endian)
    assert list(read_capture(io.BytesIO(shb + idb + epb)))[0] == (1500000000., raw, 1)


def test_identity_invariance_and_signal():
    original = parse_packet(frame(), 1)
    changed = bytearray(frame(b"\xac\x10\x00\x06", b"\xc0\xa8\x01\x05", sport=64000))
    for start, end in [(0, 12), (18, 20), (24, 26), (38, 46), (50, 52)]:
        changed[start:end] = b"\x81" * (end-start)
    assert packet_features(original) == packet_features(parse_packet(bytes(changed), 1))
    assert packet_features(original) != packet_features(parse_packet(frame(flags=18), 1))
    masked = sanitize(original)
    assert masked[:12] == bytes(12) and masked[26:36] == bytes(10)
    assert masked[36:38] == b"\x00\x50"


def test_vlan_options_ipv6_and_fragments():
    raw = frame(options=b"\x01" * 4)
    packet = parse_packet(raw[:12] + b"\x81\x00\x00\x01" + raw[12:], 1)
    assert (packet.network_offset, packet.transport_offset, packet.dport) == (18, 42, 80)
    ipv6 = b"\xaa" * 12 + b"\x86\xdd" + bytes.fromhex("6000000000180640") + b"\x11" * 32 + frame()[34:]
    packet = parse_packet(ipv6, 1)
    assert packet.version == 6 and sanitize(packet)[22:54] == bytes(32)
    fragment = bytearray(frame()); fragment[20:22] = b"\x00\x01"
    assert parse_packet(bytes(fragment), 1) is None
    ip = frame()[14:]
    cooked = bytes.fromhex("000000010006") + b"\xaa" * 8 + b"\x08\x00" + ip
    p = parse_packet(cooked, 1, 113)
    assert p.network_offset == 16 and sanitize(p)[6:14] == bytes(8)
    assert packet_features(p) == packet_features(parse_packet(frame(), 1))


def test_flow_context():
    bursts = list(flow_bursts(read_capture(io.BytesIO(pcap([frame()] * 17)))))
    # SYN flags in the fixture intentionally denote new sessions. Use ACK for
    # one established session when checking that only its first 16 are retained.
    bursts = list(flow_bursts(read_capture(io.BytesIO(pcap([frame(flags=16)] * 17)))))
    assert [len(b) for b in bursts] == [16]
    assert burst_array(bursts[0]).shape == (16, 32)
    assert not burst_array([parse_packet(frame(), 1)])[1:].any()


def test_fail_closed():
    for content in [b"garbage", pcap([frame()])[:-2]]:
        with pytest.raises(ValueError):
            list(read_capture(io.BytesIO(content)))
    assert list(read_capture(io.BytesIO(pcap([frame()])[:-2]), allow_truncated=True)) == []


def test_model_loss_calibration_rejection():
    torch.set_num_threads(2)
    output = FlowResNet()(torch.rand(4, 1, 512))
    assert output.shape == (4, 3)
    loss = FocalLoss()(output, torch.tensor([0, 1, 2, 0])); loss.backward()
    assert torch.isfinite(loss)
    assert probabilities(torch.tensor([[0., 0., 0.], [12., 0., 0.]]))[2].tolist() == [True, False]
    logits, targets = torch.tensor([[10., 0., 0.], [10., 0., 0.], [0., 10., 0.]]), torch.tensor([1, 0, 1])
    temperature = calibrate_temperature(logits, targets)
    assert torch.nn.functional.cross_entropy(logits / temperature, targets) <= torch.nn.functional.cross_entropy(logits, targets)


@pytest.fixture
def client(tmp_path, monkeypatch):
    import api.server as server
    from classification.production import get_flow_classifier
    monkeypatch.setattr(server, "DB_PATH", tmp_path / "audit.sqlite3")
    monkeypatch.setenv("TRAFFICSCAN_CHECKPOINT", str(tmp_path / "missing.pth"))
    monkeypatch.delenv("TRAFFICSCAN_API_KEY", raising=False)
    get_flow_classifier.cache_clear()
    with TestClient(server.app) as client:
        yield client
    get_flow_classifier.cache_clear()


def test_api_analysis_and_history(client):
    assert client.get("/api/health").json()["status"] == "degraded"
    assert client.get("/api/ready").status_code == 503
    response = client.post("/api/analyze/upload", files={"file": ("capture.pcap", pcap([frame()] * 20))})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["prediction"] == "unknown" and result["counts"]["unknown"] == 2
    assert result["telemetry"]["packet_count"] == 20
    assert len(result["flows"][0]["fingerprint"]) == 512
    assert client.get("/api/investigations").json()[0]["id"] == result["id"]
    assert client.get("/api/investigations/" + result["id"]).json() == result
    assert client.get("/api/investigations/absent").status_code == 404


def test_api_input_auth_and_headers(client, monkeypatch):
    import api.server as server
    assert client.post("/api/analyze/upload", files={"file": ("bad.pcap", b"bad")}).status_code == 422
    assert client.post("/api/analyze/upload", files={"file": ("x.png", b"image")}).status_code == 415
    assert client.post("/api/analyze/upload", files={"file": ("x.pcap", b"")}).status_code == 400
    monkeypatch.setattr(server, "MAX_UPLOAD", 10)
    assert client.post("/api/analyze/upload", files={"file": ("x.pcap", b"0" * 11)}).status_code == 413
    monkeypatch.setenv("TRAFFICSCAN_API_KEY", "test-secret")
    assert client.get("/api/investigations").status_code == 401
    assert client.get("/api/investigations", headers={"X-API-Key": "test-secret"}).status_code == 200
    assert "frame-ancestors 'none'" in client.get("/").headers["content-security-policy"]


def test_upload_backpressure_precedes_parsing(client):
    import api.server as server
    server.ANALYSIS_SLOT.acquire()
    try:
        response = client.post("/api/analyze/upload", content=b"unparsed invalid body")
        assert response.status_code == 429
    finally:
        server.ANALYSIS_SLOT.release()


def test_chunked_body_limit():
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from api.body_limit import UploadBodyLimit
    async def receive(request):
        return JSONResponse({"length": len(await request.body())})
    app = Starlette(routes=[Route("/api/analyze/upload", receive, methods=["POST"])])
    app.add_middleware(UploadBodyLimit, limit=4)
    with TestClient(app) as client:
        response = client.post("/api/analyze/upload", content=iter([b"abc", b"def"]))
        assert response.status_code == 413


def test_exact_flow_label_join_and_conflict(tmp_path):
    from data_processing.build_production import FlowLabels
    path = tmp_path / "labels.csv"
    path.write_text("start,end,source,destination,sport,dport,protocol,label\n1,3,10.0.0.1,10.0.0.2,55000,80,6,botnet\n")
    packet = parse_packet(frame(), 2)
    assert FlowLabels(path)(packet) == "botnet"
    assert FlowLabels(path)(parse_packet(frame(), 4)) is None
    with path.open("a") as output:
        output.write("1,3,10.0.0.1,10.0.0.2,55000,80,6,benign\n")
    assert FlowLabels(path)(packet) is None


def test_versioned_checkpoint_and_batch_inference(tmp_path, monkeypatch):
    from classification.production import FlowClassifier, CLASSES
    from data_processing.production import REPRESENTATION
    path = tmp_path / "arbitrary-filename.pth"
    torch.save(dict(architecture="flow_resnet18_1d", representation=REPRESENTATION, classes=CLASSES,
                    model_state_dict=FlowResNet().state_dict(), temperature=2., confidence_threshold=1., entropy_threshold=.8), path)
    monkeypatch.setenv("TRAFFICSCAN_CHECKPOINT", str(path))
    monkeypatch.delenv("TRAFFICSCAN_ONNX", raising=False)
    monkeypatch.delenv("TRAFFICSCAN_TENSORRT", raising=False)
    engine = FlowClassifier()
    result = engine.analyze(io.BytesIO(pcap([frame()] * 17)), "test.pcap")
    assert engine.model is not None
    assert result["counts"]["unknown"] == 2
    assert abs(sum(result["flows"][0]["probabilities"].values()) - 1) < 1e-5
    assert not engine.health()["production_ready"]
    torch.save(dict(architecture="legacy"), path)
    assert FlowClassifier().model is None


def test_tensor_normalization_matches_training():
    import numpy as np
    from classification.tensor import normalize_batch
    arrays = np.arange(512, dtype=np.uint16).astype(np.uint8).reshape(1, 16, 32)
    expected = torch.tensor(arrays.astype(np.float32).reshape(1, 1, 512) / 127.5 - 1)
    torch.testing.assert_close(normalize_batch(arrays, torch.device("cpu")), expected)


def test_http_range_validation(monkeypatch):
    from scripts import acquire_production_data as acquisition
    class Response:
        status_code = 200
        headers = {}
        content = b"unexpected full file"
        def close(self):
            pass
    monkeypatch.setattr(acquisition, "get", lambda *args, **kwargs: Response())
    with pytest.raises(ValueError, match="did not honor"):
        acquisition.range_bytes("https://example.invalid/capture", 100, 50)


def test_http_range_byte_budget(monkeypatch):
    from scripts import acquire_production_data as acquisition
    class Response:
        status_code = 206
        headers = {"Content-Range": "bytes 100-149/1000"}
        def iter_content(self, size):
            yield bytes(51)
        def close(self):
            pass
    monkeypatch.setattr(acquisition, "get", lambda *args, **kwargs: Response())
    with pytest.raises(ValueError, match="exceeded"):
        acquisition.range_bytes("https://example.invalid/capture", 100, 50)
    Response.headers = {"Content-Range": "bytes 100-159/1000"}
    with pytest.raises(ValueError, match="Content-Range"):
        acquisition.range_bytes("https://example.invalid/capture", 100, 50)


def test_native_mmap_matches_streaming_parser(tmp_path, monkeypatch):
    from data_processing import production
    if production._native is None:
        pytest.skip("Native extension tested in the Linux verification image")
    path = tmp_path / "capture.pcap"
    path.write_bytes(pcap([frame(), frame(flags=16)]))
    native = list(read_capture(path))
    monkeypatch.setattr(production, "_native", None)
    assert native == list(read_capture(path))


def test_cse_labels_require_endpoint_protocol_and_independent_day():
    from datetime import datetime
    from types import SimpleNamespace
    from scripts.prepare_cse import schedule_label, SCHEDULES, ATTACKERS, VICTIMS
    audit = dict(windows=SCHEDULES["cse"], attackers=list(ATTACKERS), victims=list(VICTIMS))
    packet = SimpleNamespace(source="18.218.115.60", destination="172.31.69.25", protocol=6,
                             timestamp=datetime.fromisoformat("2018-02-20T10:30:00-04:00").timestamp())
    assert schedule_label(packet, audit) == "ddos"
    packet.protocol = 17
    assert schedule_label(packet, audit) is None
    packet.protocol = 6
    packet.destination = "172.31.69.28"
    assert schedule_label(packet, audit) is None
    packet.destination = "172.31.69.25"
    packet.timestamp += 86400
    assert schedule_label(packet, audit) is None


def test_engine_metadata_preserves_training_report(tmp_path):
    from classification.artifacts import engine_metadata_path
    training_report = tmp_path / "model.json"
    training_report.write_text('{"accuracy": 0.98}')
    engine = tmp_path / "model.engine"
    engine_metadata_path(engine).write_text('{"engine_sha256": "example"}')
    assert training_report.read_text() == '{"accuracy": 0.98}'
    assert engine_metadata_path(engine).name == "model.engine.json"


def test_demo_does_not_count_unknown_as_correct_attack_type():
    from classification.demo import compare_case
    case = dict(id="demo-unseen", title="Unknown attack", expected_class="ddos", source_group="holdout",
                label_basis="Independent label", sha256="verified")
    result = dict(flows=[dict(prediction="unknown"), dict(prediction="benign"), dict(prediction="ddos")],
                  counts=dict(unknown=1, benign=1, ddos=1, botnet=0), telemetry=dict(analysis_ms=1))
    report = compare_case(case, result)
    assert report["class_match_rate"] == pytest.approx(1/3)
    assert report["attack_escalation_rate"] == pytest.approx(2/3)
    case["expected_class"] = "benign"
    report = compare_case(case, result)
    assert report["benign_attack_alert_rate"] == pytest.approx(1/3)
    assert report["benign_review_rate"] == pytest.approx(2/3)


def test_demo_auth_and_backpressure(client, monkeypatch):
    import api.server as server
    monkeypatch.setenv("TRAFFICSCAN_API_KEY", "demo-secret")
    assert client.post("/api/demo").status_code == 401
    server.ANALYSIS_SLOT.acquire()
    try:
        assert client.post("/api/demo", headers={"X-API-Key": "demo-secret"}).status_code == 429
    finally:
        server.ANALYSIS_SLOT.release()


def test_class_specific_policy_uses_predicted_class():
    logits = torch.tensor([[2., 1., 0.], [1., 2., 0.]])
    baseline = probabilities(logits)[2]
    selected = probabilities(logits, confidence_threshold=[.5, .9, .9], entropy_threshold=[.95, .8, .8])[2]
    assert baseline.tolist() == [True, True]
    assert selected.tolist() == [False, True]
    assert torch.equal(baseline, probabilities(logits, confidence_threshold=[.75]*3, entropy_threshold=[.8]*3)[2])


def test_replay_timeline_preserves_packet_counts_and_partial_flow_readiness(monkeypatch, tmp_path):
    from classification.production import FlowClassifier
    monkeypatch.setenv("TRAFFICSCAN_CHECKPOINT", str(tmp_path / "absent.pth"))
    monkeypatch.delenv("TRAFFICSCAN_TENSORRT", raising=False)
    engine = FlowClassifier()
    result = engine.analyze(io.BytesIO(pcap([frame(flags=16), frame(sport=55001, flags=16)])), "capture.pcap")
    assert sum(b["count"] for b in result["timeline"]["bins"]) == 2
    assert sum(b["bytes"] for b in result["timeline"]["bins"]) == result["telemetry"]["total_bytes"]
    assert all(f["ready_timestamp"] == result["timeline"]["end"] for f in result["flows"])
    assert sum(len(f["packet_timeline"]) for f in result["flows"]) == 2


def test_large_packet_timeline_is_bounded():
    from classification.timeline import packet_timeline
    timeline = packet_timeline([(float(i),60) for i in range(100000)])
    assert len(timeline["bins"]) <= 512
    assert sum(b["count"] for b in timeline["bins"]) == 100000
    assert timeline["start"] == 0 and timeline["end"] == 99999


def test_virtual_sensor_never_connects_to_arbitrary_ips(client):
    response = client.post("/api/simulate", json={"address":"8.8.8.8","scenario":"mixed"})
    assert response.status_code == 422
    assert "virtual sensor" in response.json()["detail"]


def test_workspace_assets_revalidate_after_deploy(client):
    for url in ("/", "/static/stream-core.js", "/static/stream.js", "/static/app.js"):
        response = client.get(url)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-cache"


def test_packet_log_includes_context_excess_and_unsupported_frames(monkeypatch, tmp_path):
    from classification.production import FlowClassifier
    monkeypatch.setenv("TRAFFICSCAN_CHECKPOINT", str(tmp_path / "missing.pth"))
    monkeypatch.delenv("TRAFFICSCAN_TENSORRT", raising=False)
    # 20 ACK packets: only the first 16 represent the flow; the ARP frame
    # remains in the packet log even though it is outside model coverage.
    unsupported = b"\xaa" * 12 + b"\x08\x06" + b"\x00" * 28
    frames = [frame(flags=16)] * 20 + [unsupported]
    result = FlowClassifier().analyze(io.BytesIO(pcap(frames)), "logged.pcap")
    rows = result["packet_log"]["rows"]
    assert len(rows) == result["telemetry"]["packet_count"] == 21
    assert [row[0] for row in rows] == list(range(1, 22))
    assert sum(row[2] for row in rows) == result["telemetry"]["total_bytes"]
    assert sum(f["packets"] for f in result["flows"]) == 16
    assert rows[-1][3] is None and rows[-1][7] == "Unsupported"


def test_virtual_scenarios_select_distinct_packet_content(tmp_path, monkeypatch):
    import hashlib
    import classification.simulation as simulation
    monkeypatch.setattr(simulation, "load_cases", lambda root: None)
    folder = tmp_path / "data/production/samples"
    folder.mkdir(parents=True)
    for index, name in enumerate(("demo-normal", "demo-ddos", "demo-botnet", "demo-unseen")):
        (folder / (name + ".pcap")).write_bytes(pcap([frame(payload=bytes([index]), flags=16)] * (index + 1)))
    hashes = set()
    for scenario, sources in simulation.SCENARIOS.items():
        capture, metadata = simulation.virtual_capture(tmp_path, scenario)
        rows = list(read_capture(capture))
        assert [phase["reference"] for phase in metadata["phases"]] == list(sources)
        assert metadata["packet_count"] == len(rows)
        actual = hashlib.sha256(b"".join(struct.pack("<I", len(raw)) + raw for stamp, raw, link in rows)).hexdigest()
        assert metadata["content_sha256"] == actual
        hashes.add(actual)
    assert len(hashes) == 4


def test_virtual_continuation_is_labeled_and_does_not_create_new_model_context(tmp_path, monkeypatch):
    import classification.simulation as simulation
    monkeypatch.setattr(simulation, "load_cases", lambda root: None)
    folder = tmp_path / "data/production/samples"
    folder.mkdir(parents=True)
    for index, name in enumerate(("demo-normal", "demo-ddos", "demo-botnet", "demo-unseen")):
        (folder / (name + ".pcap")).write_bytes(pcap([frame(sport=55000+index,flags=16)] * 16))
    capture, metadata = simulation.virtual_capture(tmp_path, "mixed")
    raw = capture.getvalue()
    assert metadata["synthetic_continuation_packets"] == 32
    assert metadata["packet_count"] == 96
    assert len(list(read_capture(io.BytesIO(raw)))) == 96
    bursts = list(flow_bursts(read_capture(io.BytesIO(raw))))
    assert len(bursts) == 4 and all(len(burst) == 16 for burst in bursts)
