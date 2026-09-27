import io
import uuid
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.core.scope import classify_scope
from app.investigation.hosts_repo import get_host, get_hosts, save_hosts
from app.main import app
from app.parsers.host_aggregator import aggregate_hosts
from app.schemas.host import Host
from fastapi.testclient import TestClient
from scapy.all import ARP, IP, TCP, UDP, Ether, wrpcap


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


def test_scope_classification():
    assert classify_scope("10.0.0.1") == "internal"
    assert classify_scope("172.16.0.5") == "internal"
    assert classify_scope("192.168.1.1") == "internal"
    assert classify_scope("127.0.0.1") == "internal"
    assert classify_scope("169.254.1.1") == "internal"
    assert classify_scope("224.0.0.1") == "internal"
    assert classify_scope("fe80::1") == "internal"
    assert classify_scope("fc00::1") == "internal"
    assert classify_scope("ff00::1") == "internal"
    assert classify_scope("ff02::1") == "internal"
    assert classify_scope("::1") == "internal"

    assert classify_scope("8.8.8.8") == "external"
    assert classify_scope("1.1.1.1") == "external"
    assert classify_scope("2001:4860:4860::8888") == "external"

    assert classify_scope("not-an-ip") == "unknown"
    assert classify_scope("") == "unknown"


def test_aggregate_two_host_simple(tmp_path: Path):
    pcap_path = tmp_path / "simple_two_host.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="192.168.1.10", dst="192.168.1.20"
    ) / TCP(sport=12345, dport=80)
    p1.time = 1700000000.0

    p2 = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(
        src="192.168.1.20", dst="192.168.1.10"
    ) / TCP(sport=80, dport=12345)
    p2.time = 1700000002.0

    wrpcap(str(pcap_path), [p1, p2])

    hosts = aggregate_hosts(pcap_path, "pcap", inv_id)
    assert len(hosts) == 2

    host_map = {h.ip: h for h in hosts}
    h1 = host_map["192.168.1.10"]
    h2 = host_map["192.168.1.20"]

    assert h1.investigation_id == inv_id
    assert h1.mac is None
    assert h1.scope == "internal"
    assert h1.packets_sent == 1
    assert h1.packets_received == 1
    assert h1.bytes_sent == len(p1)
    assert h1.bytes_received == len(p2)
    assert h1.unique_destinations == 1
    assert h1.unique_ports == 1

    assert h2.investigation_id == inv_id
    assert h2.mac is None
    assert h2.scope == "internal"
    assert h2.packets_sent == 1
    assert h2.packets_received == 1
    assert h2.bytes_sent == len(p2)
    assert h2.bytes_received == len(p1)
    assert h2.unique_destinations == 1
    assert h2.unique_ports == 1


def test_aggregate_counts_bytes_and_packets(tmp_path: Path):
    pcap_path = tmp_path / "bytes_packets.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="10.0.0.1", dst="10.0.0.2"
    ) / TCP(sport=1000, dport=80)
    p1.time = 1700000000.0

    p2 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="10.0.0.1", dst="10.0.0.2"
    ) / TCP(sport=1001, dport=80)
    p2.time = 1700000001.0

    p3 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="10.0.0.1", dst="10.0.0.2"
    ) / TCP(sport=1002, dport=80)
    p3.time = 1700000002.0

    packets = [p1, p2, p3]
    total_len = sum(len(pkt) for pkt in packets)
    wrpcap(str(pcap_path), packets)

    hosts = aggregate_hosts(pcap_path, "pcap", inv_id)
    assert len(hosts) == 2

    host_map = {h.ip: h for h in hosts}
    src_host = host_map["10.0.0.1"]
    dst_host = host_map["10.0.0.2"]

    assert src_host.packets_sent == 3
    assert src_host.packets_received == 0
    assert src_host.bytes_sent == total_len
    assert src_host.bytes_received == 0

    assert dst_host.packets_sent == 0
    assert dst_host.packets_received == 3
    assert dst_host.bytes_sent == 0
    assert dst_host.bytes_received == total_len


def test_aggregate_unique_destinations_and_ports(tmp_path: Path):
    pcap_path = tmp_path / "unique_dest_ports.pcap"
    inv_id = uuid.uuid4().hex

    # A sends to B:80, B:443, C:80
    p1 = Ether() / IP(src="192.168.0.10", dst="192.168.0.20") / TCP(sport=50000, dport=80)
    p1.time = 1700000000.0
    p2 = Ether() / IP(src="192.168.0.10", dst="192.168.0.20") / TCP(sport=50001, dport=443)
    p2.time = 1700000001.0
    p3 = Ether() / IP(src="192.168.0.10", dst="192.168.0.30") / TCP(sport=50002, dport=80)
    p3.time = 1700000002.0

    wrpcap(str(pcap_path), [p1, p2, p3])

    hosts = aggregate_hosts(pcap_path, "pcap", inv_id)
    host_map = {h.ip: h for h in hosts}
    a_host = host_map["192.168.0.10"]

    assert a_host.unique_destinations == 2
    assert a_host.unique_ports == 2


def test_aggregate_empty_pcap(tmp_path: Path):
    empty_pcap_path = tmp_path / "empty.pcap"
    wrpcap(str(empty_pcap_path), [])

    hosts = aggregate_hosts(empty_pcap_path, "pcap", "some_inv_id")
    assert hosts == []


def test_aggregate_mac_from_arp(tmp_path: Path):
    pcap_path = tmp_path / "arp_test.pcap"
    inv_id = uuid.uuid4().hex

    p_arp_reply = Ether() / ARP(
        op=2, psrc="10.0.0.5", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.0.0.1", hwdst="11:22:33:44:55:66"
    )
    p_arp_reply.time = 1700000000.0

    p_arp_req = Ether() / ARP(
        op=1, psrc="10.0.0.5", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.0.0.1", hwdst="11:22:33:44:55:66"
    )
    p_arp_req.time = 1700000001.0

    p_ip = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=53, dport=53)
    p_ip.time = 1700000002.0

    wrpcap(str(pcap_path), [p_arp_reply, p_arp_req, p_ip])

    hosts = aggregate_hosts(pcap_path, "pcap", inv_id)
    host_map = {h.ip: h for h in hosts}

    assert host_map["10.0.0.5"].mac == "aa:bb:cc:dd:ee:ff"
    assert host_map["10.0.0.1"].mac == "11:22:33:44:55:66"


def test_aggregate_no_mac_without_arp(tmp_path: Path):
    pcap_path = tmp_path / "no_arp.pcap"
    inv_id = uuid.uuid4().hex

    p1 = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP(
        src="192.168.1.100", dst="192.168.1.200"
    ) / TCP(sport=80, dport=8080)
    p1.time = 1700000000.0

    wrpcap(str(pcap_path), [p1])

    hosts = aggregate_hosts(pcap_path, "pcap", inv_id)
    assert len(hosts) == 2
    for host in hosts:
        assert host.mac is None


def test_aggregate_mac_only_from_arp(tmp_path: Path):
    pcap_path = tmp_path / "arp_reply_tcp.pcap"
    inv_id = uuid.uuid4().hex

    # ARP reply mapping 10.0.0.5 -> aa:bb:cc:dd:ee:ff
    p_arp = Ether() / ARP(
        op=2, psrc="10.0.0.5", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.0.0.1", hwdst="00:00:00:00:00:00"
    )
    p_arp.time = 1700000000.0

    # TCP packet from 10.0.0.5 to 10.0.0.6
    p_tcp = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP(
        src="10.0.0.5", dst="10.0.0.6"
    ) / TCP(sport=1234, dport=80)
    p_tcp.time = 1700000001.0

    wrpcap(str(pcap_path), [p_arp, p_tcp])

    hosts = aggregate_hosts(pcap_path, "pcap", inv_id)
    host_map = {h.ip: h for h in hosts}

    assert host_map["10.0.0.5"].mac == "aa:bb:cc:dd:ee:ff"
    assert host_map["10.0.0.6"].mac is None


def test_save_hosts_is_idempotent():
    inv_id = uuid.uuid4().hex
    host1 = Host(
        id=uuid.uuid4().hex,
        investigation_id=inv_id,
        ip="10.0.0.1",
        mac="00:11:22:33:44:55",
        scope="internal",
        packets_sent=5,
        packets_received=2,
        bytes_sent=500,
        bytes_received=200,
        unique_destinations=1,
        unique_ports=1,
        first_seen="2026-09-28T00:00:00+00:00",
        last_seen="2026-09-28T00:05:00+00:00",
    )
    host2 = Host(
        id=uuid.uuid4().hex,
        investigation_id=inv_id,
        ip="10.0.0.2",
        mac=None,
        scope="internal",
        packets_sent=2,
        packets_received=5,
        bytes_sent=200,
        bytes_received=500,
        unique_destinations=1,
        unique_ports=1,
        first_seen="2026-09-28T00:00:00+00:00",
        last_seen="2026-09-28T00:05:00+00:00",
    )

    with get_connection() as conn:
        save_hosts(conn, inv_id, [host1, host2])
        fetched1 = get_hosts(conn, inv_id)
        assert len(fetched1) == 2

        # Save again (same hosts or new list)
        save_hosts(conn, inv_id, [host1, host2])
        fetched2 = get_hosts(conn, inv_id)
        assert len(fetched2) == 2
        assert [h.ip for h in fetched2] == ["10.0.0.1", "10.0.0.2"]

        single = get_host(conn, inv_id, host1.id)
        assert single is not None
        assert single.ip == "10.0.0.1"

        missing = get_host(conn, inv_id, "nonexistent-id")
        assert missing is None


def test_upload_returns_aggregated_status(client: TestClient, tmp_path: Path):
    pcap_path = tmp_path / "test_upload.pcap"
    p1 = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1000, dport=80)
    p1.time = 1700000000.0
    wrpcap(str(pcap_path), [p1])
    content = pcap_path.read_bytes()

    response = client.post(
        "/api/investigations",
        files={"file": ("test_upload.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "aggregated"
    assert data["packet_count"] == 1


def test_get_hosts_endpoint(client: TestClient, tmp_path: Path):
    pcap_path = tmp_path / "test_hosts_endpoint.pcap"
    p1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="10.0.0.10", dst="8.8.8.8"
    ) / UDP(sport=50000, dport=53)
    p1.time = 1700000000.0
    wrpcap(str(pcap_path), [p1])
    content = pcap_path.read_bytes()

    upload_res = client.post(
        "/api/investigations",
        files={"file": ("test_hosts_endpoint.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")},
    )
    assert upload_res.status_code == 201
    inv_id = upload_res.json()["id"]

    # Fetch hosts
    hosts_res = client.get(f"/api/investigations/{inv_id}/hosts")
    assert hosts_res.status_code == 200
    hosts = hosts_res.json()
    assert len(hosts) == 2
    ips = [h["ip"] for h in hosts]
    assert ips == ["10.0.0.10", "8.8.8.8"]

    internal_host = next(h for h in hosts if h["ip"] == "10.0.0.10")
    assert internal_host["scope"] == "internal"
    assert internal_host["mac"] is None
    assert internal_host["packets_sent"] == 1
    assert internal_host["packets_received"] == 0
    assert internal_host["unique_destinations"] == 1
    assert internal_host["unique_ports"] == 1

    external_host = next(h for h in hosts if h["ip"] == "8.8.8.8")
    assert external_host["scope"] == "external"
    assert external_host["mac"] is None
    assert external_host["packets_sent"] == 0
    assert external_host["packets_received"] == 1

    # Test 404 on non-existent investigation
    not_found_res = client.get(f"/api/investigations/{uuid.uuid4().hex}/hosts")
    assert not_found_res.status_code == 404
