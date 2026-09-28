import io
import uuid
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.investigation.flows_repo import get_flow, get_flows, save_flows
from app.main import app
from app.parsers.flow_aggregator import aggregate_flows
from app.schemas.flow import Flow
from fastapi.testclient import TestClient
from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, wrpcap
from scapy.layers.inet6 import ICMPv6EchoRequest


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    test_upload_dir = tmp_path / "uploads"
    test_tmp_dir = tmp_path / "tmp"
    test_db_path = tmp_path / "test_tuco.db"

    test_upload_dir.mkdir(parents=True, exist_ok=True)
    test_tmp_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "UPLOAD_DIR", test_upload_dir)
    monkeypatch.setattr(config, "TMP_DIR", test_tmp_dir)
    monkeypatch.setattr(config, "DB_PATH", test_db_path)

    init_db()

    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_canonicalization_same_flow_both_directions(tmp_path: Path):
    pcap_path = tmp_path / "bidirectional.pcap"
    inv_id = uuid.uuid4().hex

    # A: 192.168.1.10:12345 -> B: 192.168.1.20:80
    p1 = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="S")
    p1.time = 1700000000.0

    # B: 192.168.1.20:80 -> A: 192.168.1.10:12345
    p2 = Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=12345, flags="SA")
    p2.time = 1700000001.0

    wrpcap(str(pcap_path), [p1, p2])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1

    flow = flows[0]
    assert flow.investigation_id == inv_id
    assert flow.src_ip == "192.168.1.10"
    assert flow.src_port == 12345
    assert flow.dst_ip == "192.168.1.20"
    assert flow.dst_port == 80
    assert flow.protocol == "TCP"
    assert flow.packets_sent == 1
    assert flow.packets_received == 1
    assert flow.bytes_sent == len(p1)
    assert flow.bytes_received == len(p2)


def test_canonicalization_ip_comparison(tmp_path: Path):
    pcap_path = tmp_path / "reverse_order.pcap"
    inv_id = uuid.uuid4().hex

    # B ("192.168.1.20" - larger string) sends first to A ("192.168.1.10" - smaller string)
    p1 = Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5000, dport=53)
    p1.time = 1700000000.0

    # A sends reply to B
    p2 = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=53, dport=5000)
    p2.time = 1700000001.0

    wrpcap(str(pcap_path), [p1, p2])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1

    flow = flows[0]
    # Smaller IP string (192.168.1.10) must be canonical src_ip
    assert flow.src_ip == "192.168.1.10"
    assert flow.src_port == 53
    assert flow.dst_ip == "192.168.1.20"
    assert flow.dst_port == 5000
    assert flow.protocol == "UDP"
    # p1 was sent from 192.168.1.20 -> 192.168.1.10 (dst -> src), so it's received
    # p2 was sent from 192.168.1.10 -> 192.168.1.20 (src -> dst), so it's sent
    assert flow.packets_sent == 1
    assert flow.packets_received == 1
    assert flow.bytes_sent == len(p2)
    assert flow.bytes_received == len(p1)


def test_tcp_state_established(tmp_path: Path):
    pcap_path = tmp_path / "tcp_established.pcap"
    inv_id = uuid.uuid4().hex

    # SYN
    p1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="S")
    p1.time = 1700000000.0
    # SYN+ACK
    p2 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1000, flags="SA")
    p2.time = 1700000001.0
    # ACK
    p3 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="A")
    p3.time = 1700000002.0

    wrpcap(str(pcap_path), [p1, p2, p3])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    assert flows[0].tcp_state == "established"


def test_tcp_state_syn_only(tmp_path: Path):
    pcap_path = tmp_path / "tcp_syn_only.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="S")
    p1.time = 1700000000.0

    wrpcap(str(pcap_path), [p1])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    assert flows[0].tcp_state == "syn_sent"


def test_tcp_state_reset(tmp_path: Path):
    pcap_path = tmp_path / "tcp_reset.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="S")
    p1.time = 1700000000.0
    p2 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1000, flags="R")
    p2.time = 1700000001.0

    wrpcap(str(pcap_path), [p1, p2])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    assert flows[0].tcp_state == "reset"


def test_tcp_state_closed(tmp_path: Path):
    pcap_path = tmp_path / "tcp_closed.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="S")
    p1.time = 1700000000.0
    p2 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1000, flags="SA")
    p2.time = 1700000001.0
    # FIN from src
    p3 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="FA")
    p3.time = 1700000002.0
    # FIN from dst
    p4 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1000, flags="FA")
    p4.time = 1700000003.0

    wrpcap(str(pcap_path), [p1, p2, p3, p4])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    assert flows[0].tcp_state == "closed"


def test_tcp_state_unknown(tmp_path: Path):
    pcap_path = tmp_path / "tcp_unknown.pcap"
    inv_id = uuid.uuid4().hex

    # Only an ACK / mid-stream packet without SYN/FIN/RST
    p1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="A")
    p1.time = 1700000000.0

    wrpcap(str(pcap_path), [p1])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    assert flows[0].tcp_state == "unknown"


def test_udp_flow_has_no_tcp_state(tmp_path: Path):
    pcap_path = tmp_path / "udp_flow.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=53)
    p1.time = 1700000000.0

    wrpcap(str(pcap_path), [p1])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    assert flows[0].protocol == "UDP"
    assert flows[0].tcp_state is None


def test_icmp_flow_uses_zero_ports(tmp_path: Path):
    pcap_path = tmp_path / "icmp_flow.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether() / IP(src="192.168.1.1", dst="192.168.1.254") / ICMP(type=8)
    p1.time = 1700000000.0

    wrpcap(str(pcap_path), [p1])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.protocol == "ICMP"
    assert flow.src_port == 0
    assert flow.dst_port == 0
    assert flow.src_ip == "192.168.1.1"
    assert flow.dst_ip == "192.168.1.254"
    assert flow.tcp_state is None


def test_icmpv6_flow_uses_zero_ports(tmp_path: Path):
    pcap_path = tmp_path / "icmpv6_flow.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether() / IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest()
    p1.time = 1700000000.0

    wrpcap(str(pcap_path), [p1])

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.protocol == "ICMPv6"
    assert flow.src_port == 0
    assert flow.dst_port == 0
    assert flow.src_ip == "fe80::1"
    assert flow.dst_ip == "fe80::2"
    assert flow.tcp_state is None


def test_flow_byte_counts(tmp_path: Path):
    pcap_path = tmp_path / "byte_counts.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80)
    p1.time = 1700000000.0
    p2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80)
    p2.time = 1700000001.0
    p3 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80)
    p3.time = 1700000002.0

    packets = [p1, p2, p3]
    total_len = sum(len(pkt) for pkt in packets)
    wrpcap(str(pcap_path), packets)

    flows = aggregate_flows(pcap_path, "pcap", inv_id)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.packets_sent == 3
    assert flow.packets_received == 0
    assert flow.bytes_sent == total_len
    assert flow.bytes_received == 0


def test_save_flows_is_idempotent():
    inv_id = uuid.uuid4().hex
    flow1 = Flow(
        id=uuid.uuid4().hex,
        investigation_id=inv_id,
        src_ip="10.0.0.1",
        src_port=1000,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="TCP",
        packets_sent=5,
        packets_received=3,
        bytes_sent=500,
        bytes_received=300,
        first_seen="2026-09-28T00:00:00+00:00",
        last_seen="2026-09-28T00:05:00+00:00",
        tcp_state="established",
    )
    flow2 = Flow(
        id=uuid.uuid4().hex,
        investigation_id=inv_id,
        src_ip="10.0.0.1",
        src_port=5000,
        dst_ip="8.8.8.8",
        dst_port=53,
        protocol="UDP",
        packets_sent=1,
        packets_received=1,
        bytes_sent=60,
        bytes_received=120,
        first_seen="2026-09-28T00:01:00+00:00",
        last_seen="2026-09-28T00:01:01+00:00",
        tcp_state=None,
    )

    with get_connection() as conn:
        save_flows(conn, inv_id, [flow1, flow2])
        fetched1 = get_flows(conn, inv_id)
        assert len(fetched1) == 2

        # Save again
        save_flows(conn, inv_id, [flow1, flow2])
        fetched2 = get_flows(conn, inv_id)
        assert len(fetched2) == 2
        assert [f.protocol for f in fetched2] == ["TCP", "UDP"]

        single = get_flow(conn, inv_id, flow1.id)
        assert single is not None
        assert single.src_ip == "10.0.0.1"

        missing = get_flow(conn, inv_id, "nonexistent-id")
        assert missing is None


def test_upload_returns_aggregated_with_flows(client: TestClient, tmp_path: Path):
    pcap_path = tmp_path / "test_upload_flows.pcap"
    p1 = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1000, dport=80, flags="S")
    p1.time = 1700000000.0
    wrpcap(str(pcap_path), [p1])
    content = pcap_path.read_bytes()

    upload_res = client.post(
        "/api/investigations",
        files={"file": ("test_upload_flows.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")},
    )

    assert upload_res.status_code == 201
    data = upload_res.json()
    assert data["status"] == "aggregated"
    inv_id = data["id"]

    # GET /flows
    flows_res = client.get(f"/api/investigations/{inv_id}/flows")
    assert flows_res.status_code == 200
    flows = flows_res.json()
    assert len(flows) > 0
    assert flows[0]["src_ip"] == "192.168.1.1"
    assert flows[0]["dst_ip"] == "192.168.1.2"
    assert flows[0]["src_port"] == 1000
    assert flows[0]["dst_port"] == 80
    assert flows[0]["protocol"] == "TCP"
    assert flows[0]["tcp_state"] == "syn_sent"

    # 404 check
    not_found = client.get(f"/api/investigations/{uuid.uuid4().hex}/flows")
    assert not_found.status_code == 404
