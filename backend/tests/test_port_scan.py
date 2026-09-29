from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.detections.base import DetectionContext, DetectionEngine
from app.detections.port_scan import PortScanDetector
from app.detections.registry import build_default_engine
from app.investigation.detections_repo import get_detections, save_detections
from app.main import app
from app.schemas.flow import Flow
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether, wrpcap


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    upload_dir = tmp_path / "uploads"
    tmp_dir = tmp_path / "tmp"
    upload_dir.mkdir()
    tmp_dir.mkdir()
    monkeypatch.setattr(config, "UPLOAD_DIR", upload_dir)
    monkeypatch.setattr(config, "TMP_DIR", tmp_dir)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_tuco.db")
    init_db()


def make_flow(
    flow_id: str,
    source_ip: str,
    target_ip: str,
    port: int,
    timestamp: datetime,
    *,
    reverse: bool = False,
) -> Flow:
    if reverse:
        return Flow(
            id=flow_id,
            investigation_id="investigation-1",
            src_ip=target_ip,
            src_port=port,
            dst_ip=source_ip,
            dst_port=40000 + port,
            protocol="TCP",
            packets_sent=0,
            packets_received=1,
            bytes_sent=0,
            bytes_received=60,
            first_seen=timestamp.isoformat(),
            last_seen=timestamp.isoformat(),
        )
    return Flow(
        id=flow_id,
        investigation_id="investigation-1",
        src_ip=source_ip,
        src_port=40000 + port,
        dst_ip=target_ip,
        dst_port=port,
        protocol="TCP",
        packets_sent=1,
        packets_received=0,
        bytes_sent=60,
        bytes_received=0,
        first_seen=timestamp.isoformat(),
        last_seen=timestamp.isoformat(),
    )


def run_detector(flows: list[Flow]):
    context = DetectionContext("investigation-1", [], flows, [], [])
    return build_default_engine().run(context)


def test_port_scan_fires_above_threshold():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(f"flow-{port}", "10.0.0.1", "10.0.0.2", port, start + timedelta(seconds=port / 5))
        for port in range(25)
    ]

    detections = run_detector(flows)

    assert len(detections) == 1
    detection = detections[0]
    assert detection.rule_id == "port_scan_v1"
    assert detection.observed_value == 25
    assert detection.source_ip == "10.0.0.1"
    assert detection.destination_ip == "10.0.0.2"
    assert {item["id"] for item in detection.evidence} == {flow.id for flow in flows}


def test_port_scan_does_not_fire_below_threshold():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [make_flow(str(port), "10.0.0.1", "10.0.0.2", port, start) for port in range(15)]

    assert run_detector(flows) == []


def test_port_scan_does_not_fire_outside_window():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(str(port), "10.0.0.1", "10.0.0.2", port, start + timedelta(seconds=port * 2.5))
        for port in range(25)
    ]

    assert run_detector(flows) == []


def test_port_scan_handles_canonicalization():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(str(port), "192.168.1.5", "10.0.0.1", port, start, reverse=True)
        for port in range(25)
    ]

    detections = run_detector(flows)

    assert len(detections) == 1
    assert detections[0].source_ip == "192.168.1.5"
    assert detections[0].destination_ip == "10.0.0.1"


def test_port_scan_ignores_unreplied_only_once_per_pair():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [make_flow(str(port), "10.0.0.1", "10.0.0.2", port, start) for port in range(50)]

    detections = run_detector(flows)

    assert len(detections) == 1
    assert detections[0].observed_value == 50


def test_port_scan_skips_malformed_flow():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [make_flow(str(port), "10.0.0.1", "10.0.0.2", port, start) for port in range(25)]
    flows.append(object())

    assert len(run_detector(flows)) == 1


def test_save_detections_is_idempotent():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    detection = run_detector(
        [make_flow(str(port), "10.0.0.1", "10.0.0.2", port, start) for port in range(25)]
    )[0]

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ("investigation-1", "scan.pcap", "pcap", 1, "aggregated", start.isoformat()),
        )
        save_detections(conn, "investigation-1", [detection])
        save_detections(conn, "investigation-1", [detection])
        assert len(get_detections(conn, "investigation-1")) == 1


def test_detections_endpoint_returns_empty_for_existing_investigation():
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "investigation-1",
                "empty.pcap",
                "pcap",
                0,
                "aggregated",
                datetime.now(UTC).isoformat(),
            ),
        )

    with TestClient(app) as client:
        response = client.get("/api/investigations/investigation-1/detections")

    assert response.status_code == 200
    assert response.json() == []


def test_detections_endpoint_returns_404_for_missing_investigation():
    with TestClient(app) as client:
        response = client.get("/api/investigations/missing/detections")

    assert response.status_code == 404


def test_upload_returns_aggregated_with_detections(tmp_path: Path):
    packets = []
    start = 1704067200.0
    for port in range(25):
        packet = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=40000 + port, dport=port, flags="S")
        )
        packet.time = start + port / 5
        packets.append(packet)
    pcap_path = tmp_path / "scan.pcap"
    wrpcap(str(pcap_path), packets)

    with TestClient(app) as client, pcap_path.open("rb") as capture:
        upload_response = client.post(
            "/api/investigations",
            files={"file": ("scan.pcap", capture, "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        investigation = upload_response.json()
        assert investigation["status"] == "aggregated"

        detection_response = client.get(f"/api/investigations/{investigation['id']}/detections")

    assert detection_response.status_code == 200
    assert len(detection_response.json()) >= 1
    assert detection_response.json()[0]["rule_id"] == "port_scan_v1"


def test_detection_engine_continues_after_detector_failure():
    class BrokenDetector(PortScanDetector):
        rule_id = "broken"

        def detect(self, context):
            raise RuntimeError("test failure")

    engine = DetectionEngine()
    engine.register(BrokenDetector())
    engine.register(PortScanDetector())
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [make_flow(str(port), "10.0.0.1", "10.0.0.2", port, start) for port in range(25)]

    assert len(engine.run(DetectionContext("investigation-1", [], flows, [], []))) == 1
