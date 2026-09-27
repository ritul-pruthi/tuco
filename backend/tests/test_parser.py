import io
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.main import app
from app.parsers.pcap_parser import parse_pcap
from fastapi.testclient import TestClient
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, IPv6, wrpcap
from scapy.layers.inet6 import ICMPv6EchoRequest
from scapy.utils import PcapNgWriter


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


def create_sample_tcp_packets():
    p1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="192.168.1.10", dst="192.168.1.20"
    ) / TCP(sport=12345, dport=80)
    p1.time = 1700000000.0

    p2 = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(
        src="192.168.1.20", dst="192.168.1.10"
    ) / TCP(sport=80, dport=12345)
    p2.time = 1700000002.5

    p3 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="192.168.1.10", dst="192.168.1.20"
    ) / TCP(sport=12345, dport=80)
    p3.time = 1700000005.0

    return [p1, p2, p3]


def test_parse_empty_pcap(tmp_path: Path):
    empty_pcap_path = tmp_path / "empty.pcap"
    wrpcap(str(empty_pcap_path), [])

    summary = parse_pcap(empty_pcap_path, "pcap")
    assert summary.packet_count == 0
    assert summary.first_timestamp is None
    assert summary.last_timestamp is None
    assert summary.duration_seconds is None
    assert summary.protocols == []
    assert summary.ipv4_addresses == []
    assert summary.ipv6_addresses == []


def test_parse_empty_pcapng(tmp_path: Path):
    empty_pcapng_path = tmp_path / "empty.pcapng"
    writer = PcapNgWriter(str(empty_pcapng_path))
    writer.close()

    summary = parse_pcap(empty_pcapng_path, "pcapng")
    assert summary.packet_count == 0
    assert summary.first_timestamp is None
    assert summary.last_timestamp is None
    assert summary.duration_seconds is None
    assert summary.protocols == []
    assert summary.ipv4_addresses == []
    assert summary.ipv6_addresses == []


def test_parse_basic_pcap(tmp_path: Path):
    pcap_path = tmp_path / "basic.pcap"
    packets = create_sample_tcp_packets()
    wrpcap(str(pcap_path), packets)

    summary = parse_pcap(pcap_path, "pcap")
    assert summary.packet_count == 3
    assert summary.first_timestamp == 1700000000.0
    assert summary.last_timestamp == 1700000005.0
    assert summary.duration_seconds == 5.0
    assert "TCP" in summary.protocols
    assert summary.ipv4_addresses == ["192.168.1.10", "192.168.1.20"]
    assert summary.ipv6_addresses == []


def test_parse_basic_pcapng(tmp_path: Path):
    pcapng_path = tmp_path / "basic.pcapng"
    packets = create_sample_tcp_packets()
    writer = PcapNgWriter(str(pcapng_path))
    for pkt in packets:
        writer.write(pkt)
    writer.close()

    summary = parse_pcap(pcapng_path, "pcapng")
    assert summary.packet_count == 3
    assert summary.first_timestamp == 1700000000.0
    assert summary.last_timestamp == 1700000005.0
    assert summary.duration_seconds == 5.0
    assert "TCP" in summary.protocols
    assert summary.ipv4_addresses == ["192.168.1.10", "192.168.1.20"]
    assert summary.ipv6_addresses == []


def test_parse_malformed_file(tmp_path: Path):
    bad_pcap_path = tmp_path / "malformed.pcap"
    bad_pcap_path.write_bytes(b"RANDOM_MALFORMED_BYTES_NOT_A_VALID_PCAP")

    with pytest.raises(ValueError, match="Failed to parse capture file"):
        parse_pcap(bad_pcap_path, "pcap")


def test_parse_unsupported_format(tmp_path: Path):
    test_file = tmp_path / "test.unknown"
    test_file.write_bytes(b"content")

    with pytest.raises(ValueError, match="Unsupported capture file format"):
        parse_pcap(test_file, "unknown")


def test_parse_nonexistent_file(tmp_path: Path):
    nonexistent = tmp_path / "does_not_exist.pcap"

    with pytest.raises(ValueError, match="Capture file does not exist"):
        parse_pcap(nonexistent, "pcap")


def test_parse_multi_protocol_and_ipv6(tmp_path: Path):
    pcap_path = tmp_path / "multi_protocol.pcap"

    p_udp_dns = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="10.0.0.5", dst="8.8.8.8"
    ) / UDP(sport=5353, dport=53) / DNS(qd=DNSQR(qname="example.com"))
    p_udp_dns.time = 1700000010.0

    p_icmp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="10.0.0.5", dst="10.0.0.1"
    ) / ICMP()
    p_icmp.time = 1700000011.0

    p_arp = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        psrc="10.0.0.5", pdst="10.0.0.1"
    )
    p_arp.time = 1700000012.0

    p_ipv6_icmp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IPv6(
        src="2001:db8::1", dst="2001:db8::2"
    ) / ICMPv6EchoRequest()
    p_ipv6_icmp.time = 1700000013.0

    wrpcap(str(pcap_path), [p_udp_dns, p_icmp, p_arp, p_ipv6_icmp])

    summary = parse_pcap(pcap_path, "pcap")
    assert summary.packet_count == 4
    assert summary.first_timestamp == 1700000010.0
    assert summary.last_timestamp == 1700000013.0
    assert summary.duration_seconds == 3.0
    assert set(summary.protocols) == {"UDP", "DNS", "ICMP", "ARP", "ICMPv6"}
    assert summary.ipv4_addresses == ["10.0.0.1", "10.0.0.5", "8.8.8.8"]
    assert summary.ipv6_addresses == ["2001:db8::1", "2001:db8::2"]


def test_upload_returns_parsed_status(client: TestClient, tmp_path: Path):
    pcap_path = tmp_path / "test_upload.pcap"
    packets = create_sample_tcp_packets()
    wrpcap(str(pcap_path), packets)
    content = pcap_path.read_bytes()

    response = client.post(
        "/api/investigations",
        files={"file": ("test_upload.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "parsed"
    assert data["packet_count"] == 3
    assert data["started_at"] is not None
    assert data["ended_at"] is not None
    assert data["duration_seconds"] == 5.0

    with get_connection() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id = ?", (data["id"],)).fetchone()
        assert row is not None
        assert row["status"] == "parsed"
        assert row["packet_count"] == 3
        assert row["duration_seconds"] == 5.0


def test_upload_corrupted_pcap_returns_failed_status_and_retains_file(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    # Passes magic byte check of upload endpoint (4 bytes), but fails full pcap parsing
    corrupted_pcap_bytes = b"\xd4\xc3\xb2\xa1"

    response = client.post(
        "/api/investigations",
        files={"file": ("corrupted.pcap", io.BytesIO(corrupted_pcap_bytes), "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "failed"
    assert data["packet_count"] is None

    # Verify retained in uploads directory
    uploaded_files = list(config.UPLOAD_DIR.iterdir())
    assert len(uploaded_files) == 1

    # Verify row in DB has status="failed"
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id = ?", (data["id"],)).fetchone()
        assert row is not None
        assert row["status"] == "failed"
