from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core import config
from app.core.db import init_db
from app.detections.base import DetectionContext
from app.detections.registry import build_default_engine
from app.schemas.flow import Flow


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
    timestamp: datetime,
    *,
    port: int = 443,
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


def run_engine(flows: list[Flow]):
    context = DetectionContext("investigation-1", [], flows, [], [])
    return build_default_engine().run(context)


def recon_detections(flows: list[Flow]):
    return [
        detection for detection in run_engine(flows) if detection.rule_id == "internal_recon_v1"
    ]


def test_internal_recon_fires_above_threshold():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(
            f"flow-{index}",
            "192.168.1.100",
            f"10.0.0.{index}",
            start + timedelta(seconds=index * 2),
        )
        for index in range(1, 9)
    ]

    detections = recon_detections(flows)

    assert len(detections) == 1
    assert detections[0].rule_id == "internal_recon_v1"
    assert detections[0].source_ip == "192.168.1.100"
    assert detections[0].observed_value == 8


def test_internal_recon_does_not_fire_below_threshold():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(str(index), "192.168.1.100", f"10.0.0.{index}", start) for index in range(1, 4)
    ]

    assert recon_detections(flows) == []


def test_internal_recon_does_not_fire_outside_window():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(
            f"flow-{index}",
            "192.168.1.100",
            f"10.0.0.{index}",
            start + timedelta(seconds=index * 12),
        )
        for index in range(1, 9)
    ]

    assert recon_detections(flows) == []


def test_internal_recon_ignores_external_targets():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    targets = [
        "8.8.8.8",
        "1.1.1.1",
        "9.9.9.9",
        "4.2.2.2",
        "208.67.222.222",
        "8.8.4.4",
        "1.0.0.1",
        "9.9.9.10",
        "4.2.2.1",
        "208.67.220.220",
    ]
    flows = [
        make_flow(f"flow-{index}", "192.168.1.100", target, start)
        for index, target in enumerate(targets)
    ]

    assert recon_detections(flows) == []


def test_internal_recon_ignores_external_scanner():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(f"flow-{index}", "8.8.8.8", f"10.0.0.{index}", start, reverse=True)
        for index in range(1, 11)
    ]

    assert recon_detections(flows) == []


def test_internal_recon_canonicalization():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(f"flow-{index}", "192.168.1.100", f"10.0.0.{index}", start, reverse=True)
        for index in range(1, 9)
    ]

    detections = recon_detections(flows)

    assert len(detections) == 1
    assert detections[0].source_ip == "192.168.1.100"
    assert detections[0].destination_ip == "multiple"


def test_internal_recon_one_detection_per_scanner():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    flows = [
        make_flow(
            f"flow-{index}", "192.168.1.100", f"10.0.0.{index}", start + timedelta(seconds=index)
        )
        for index in range(1, 21)
    ]

    detections = recon_detections(flows)

    assert len(detections) == 1
    assert detections[0].observed_value == 20


def test_port_scan_and_internal_recon_coexist():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    port_scan_flows = [
        make_flow(f"port-{port}", "10.0.0.50", "10.0.0.60", start, port=port) for port in range(20)
    ]
    recon_flows = [
        make_flow(
            f"recon-{index}", "192.168.1.100", f"10.0.0.{index}", start + timedelta(seconds=index)
        )
        for index in range(1, 9)
    ]

    rule_ids = {detection.rule_id for detection in run_engine(port_scan_flows + recon_flows)}

    assert rule_ids == {"port_scan_v1", "internal_recon_v1"}
