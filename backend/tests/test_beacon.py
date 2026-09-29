from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core import config
from app.core.db import init_db
from app.detections.base import DetectionContext
from app.detections.registry import build_default_engine
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
    destination_ip: str,
    timestamp: datetime,
    *,
    destination_port: int = 443,
    protocol: str = "TCP",
    first_seen: str | None = None,
) -> Flow:
    timestamp_text = first_seen if first_seen is not None else timestamp.isoformat()
    return Flow(
        id=flow_id,
        investigation_id="investigation-1",
        src_ip=source_ip,
        src_port=40000 + int(flow_id.split("-")[-1]) if flow_id.split("-")[-1].isdigit() else 40000,
        dst_ip=destination_ip,
        dst_port=destination_port,
        protocol=protocol,
        packets_sent=1,
        packets_received=0,
        bytes_sent=60,
        bytes_received=0,
        first_seen=timestamp_text,
        last_seen=timestamp_text,
    )


def run_engine(flows: list[Flow]):
    context = DetectionContext("investigation-1", [], flows, [], [])
    return build_default_engine().run(context)


def beacon_detections(flows: list[Flow]):
    return [detection for detection in run_engine(flows) if detection.rule_id == "beacon_v1"]


def regular_flows(
    start: datetime,
    *,
    destination_ip: str = "8.8.8.8",
    count: int = 10,
    interval: float = 10,
    jitter: list[float] | None = None,
) -> list[Flow]:
    offsets = jitter or [index * interval for index in range(count)]
    return [
        make_flow(
            f"flow-{index}",
            "10.0.0.5",
            destination_ip,
            start + timedelta(seconds=offset),
        )
        for index, offset in enumerate(offsets)
    ]


def test_beacon_fires_on_regular_interval():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    detections = beacon_detections(
        regular_flows(start, jitter=[0, 10.1, 19.9, 30.0, 40.1, 50.0, 60.0, 70.1, 80.0, 90.0])
    )

    assert len(detections) == 1
    detection = detections[0]
    assert detection.rule_id == "beacon_v1"
    assert detection.destination_ip == "8.8.8.8"
    assert detection.destination_port == 443
    assert detection.observed_value == 9
    assert "9 intervals with 0.01 regularity" == detection.observed_metric
    assert "mean interval of 10.0 seconds" in detection.explanation


def test_beacon_does_not_fire_below_min_observations():
    start = datetime(2024, 1, 1, tzinfo=UTC)

    assert beacon_detections(regular_flows(start, count=5, interval=20)) == []


def test_beacon_does_not_fire_on_short_duration():
    start = datetime(2024, 1, 1, tzinfo=UTC)

    assert beacon_detections(regular_flows(start, count=12, interval=20 / 11)) == []


def test_beacon_does_not_fire_on_irregular_intervals():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    offsets = [0, 2, 20, 21, 45, 46, 70, 71, 90, 91, 120, 121]

    assert beacon_detections(regular_flows(start, count=12, jitter=offsets)) == []


def test_beacon_only_groups_by_destination_tuple():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = regular_flows(start) + regular_flows(start, destination_ip="1.1.1.1")

    detections = beacon_detections(flows)

    assert len(detections) == 2
    assert {detection.destination_ip for detection in detections} == {"8.8.8.8", "1.1.1.1"}


def test_beacon_ignores_sub_second_intervals():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    offsets = [0, 0.5, 10, 10.5, 20, 20.5, 30, 30.5, 40, 40.5, 50, 50.5, 60, 60.5, 70]

    assert beacon_detections(regular_flows(start, count=len(offsets), jitter=offsets)) == []


def test_beacon_handles_malformed_timestamp():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = regular_flows(start)
    flows.append(make_flow("flow-bad", "10.0.0.5", "8.8.8.8", start, first_seen="not-a-timestamp"))

    detections = beacon_detections(flows)

    assert len(detections) == 1
    assert len(detections[0].evidence) == 10


def test_upload_returns_aggregated_with_beacon(tmp_path: Path):
    packets = []
    start = 1704067200.0
    for index in range(10):
        packet = (
            Ether()
            / IP(src="10.0.0.5", dst="8.8.8.8")
            / TCP(sport=40000 + index, dport=443, flags="S")
        )
        packet.time = start + index * 10
        packets.append(packet)
    pcap_path = tmp_path / "beacon.pcap"
    wrpcap(str(pcap_path), packets)

    with TestClient(app) as client, pcap_path.open("rb") as capture:
        upload_response = client.post(
            "/api/investigations",
            files={"file": ("beacon.pcap", capture, "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        investigation = upload_response.json()
        assert investigation["status"] == "aggregated"

        detections_response = client.get(f"/api/investigations/{investigation['id']}/detections")

    assert detections_response.status_code == 200
    assert any(item["rule_id"] == "beacon_v1" for item in detections_response.json())
