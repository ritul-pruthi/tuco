import io
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.detections.base import DetectionContext
from app.detections.config import LARGE_OUTBOUND_MIN_BYTES
from app.detections.large_transfer import LargeOutboundTransferDetector
from app.investigation.detections_repo import get_detections, save_detections
from app.main import app
from app.schemas.flow import Flow
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether, Raw, wrpcap


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
    src_ip: str,
    dst_ip: str,
    bytes_sent: int,
    timestamp: datetime,
    *,
    packets_sent: int = 1,
    packets_received: int = 0,
    bytes_received: int = 0,
    src_port: int = 50000,
    dst_port: int = 443,
) -> Flow:
    return Flow(
        id=flow_id,
        investigation_id="investigation-1",
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="TCP",
        packets_sent=packets_sent,
        packets_received=packets_received,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        first_seen=timestamp.isoformat(),
        last_seen=timestamp.isoformat(),
    )


def detect(flows: list[Flow | object]):
    context = DetectionContext("investigation-1", [], flows, [], [])
    return LargeOutboundTransferDetector().detect(context)


def test_large_outbound_fires():
    flow = make_flow(
        "large", "10.0.0.5", "8.8.8.8", LARGE_OUTBOUND_MIN_BYTES + 1, datetime.now(UTC)
    )

    detections = detect([flow])

    assert len(detections) == 1
    detection = detections[0]
    assert detection.rule_id == "large_outbound_transfer_v1"
    assert detection.source_ip == "10.0.0.5"
    assert detection.destination_ip == "8.8.8.8"
    assert detection.source_port == 50000
    assert detection.destination_port == 443
    assert detection.observed_value == LARGE_OUTBOUND_MIN_BYTES + 1
    assert "10.0.0.5" in detection.explanation
    assert "8.8.8.8" in detection.explanation
    assert "TCP" in detection.explanation
    assert "443" in detection.explanation


def test_large_outbound_does_not_fire_below_threshold():
    flow = make_flow("small", "10.0.0.5", "8.8.8.8", 5 * 1024 * 1024, datetime.now(UTC))

    assert detect([flow]) == []


def test_large_outbound_does_not_fire_internal_to_internal():
    flow = make_flow("internal", "10.0.0.5", "10.0.0.6", 20 * 1024 * 1024, datetime.now(UTC))

    assert detect([flow]) == []


def test_large_outbound_does_not_fire_external_to_internal():
    flow = make_flow("external", "8.8.8.8", "10.0.0.5", 20 * 1024 * 1024, datetime.now(UTC))

    assert detect([flow]) == []


def test_large_outbound_handles_reverse_canonicalization():
    flow = make_flow(
        "reverse",
        "8.8.8.8",
        "192.168.1.5",
        0,
        datetime.now(UTC),
        packets_sent=0,
        packets_received=1,
        bytes_received=20 * 1024 * 1024,
        src_port=443,
        dst_port=51000,
    )

    detections = detect([flow])

    assert len(detections) == 1
    assert detections[0].source_ip == "192.168.1.5"
    assert detections[0].source_port == 51000
    assert detections[0].destination_ip == "8.8.8.8"
    assert detections[0].destination_port == 443


def test_large_outbound_sorts_by_bytes_descending():
    timestamp = datetime.now(UTC)
    flows = [
        make_flow("small-large", "10.0.0.5", "8.8.8.8", 11 * 1024 * 1024, timestamp),
        make_flow("largest", "10.0.0.6", "1.1.1.1", 30 * 1024 * 1024, timestamp),
    ]

    detections = detect(flows)

    assert [detection.observed_value for detection in detections] == [
        30 * 1024 * 1024,
        11 * 1024 * 1024,
    ]


def test_large_outbound_skips_malformed_flows():
    flow = make_flow("malformed", "10.0.0.5", "8.8.8.8", 20 * 1024 * 1024, datetime.now(UTC))
    malformed_timestamp = flow.model_copy(update={"first_seen": "not-a-timestamp"})

    assert detect([malformed_timestamp, object()]) == []


def test_save_detections_is_idempotent():
    flow = make_flow("large", "10.0.0.5", "8.8.8.8", 20 * 1024 * 1024, datetime.now(UTC))
    detection = detect([flow])[0]

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "investigation-1",
                "large.pcap",
                "pcap",
                1,
                "aggregated",
                datetime.now(UTC).isoformat(),
            ),
        )
        save_detections(conn, "investigation-1", [detection])
        save_detections(conn, "investigation-1", [detection])

        assert len(get_detections(conn, "investigation-1")) == 1


def test_detections_endpoint_returns_empty_for_existing_investigation():
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
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


def test_upload_returns_aggregated_with_large_transfer(tmp_path: Path):
    packets = []
    for index in range(176):
        packet = (
            Ether()
            / IP(src="192.168.1.5", dst="8.8.8.8")
            / TCP(sport=51000, dport=443, flags="PA", seq=index * 60000)
            / Raw(load=b"x" * 60000)
        )
        packet.time = 1704067200.0 + index
        packets.append(packet)
    pcap_path = tmp_path / "large-transfer.pcap"
    wrpcap(str(pcap_path), packets)

    with TestClient(app) as client, pcap_path.open("rb") as capture:
        upload_response = client.post(
            "/api/investigations",
            files={
                "file": (
                    "large-transfer.pcap",
                    io.BytesIO(capture.read()),
                    "application/octet-stream",
                )
            },
        )

    assert upload_response.status_code == 201
    investigation = upload_response.json()
    assert investigation["status"] == "aggregated"
    detections_response = client.get(f"/api/investigations/{investigation['id']}/detections")

    assert detections_response.status_code == 200
    assert any(
        item["rule_id"] == "large_outbound_transfer_v1" for item in detections_response.json()
    )
