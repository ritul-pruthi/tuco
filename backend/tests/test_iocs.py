import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.investigation.dns_repo import save_dns_records
from app.investigation.flows_repo import save_flows
from app.investigation.hosts_repo import save_hosts
from app.investigation.http_repo import save_http_records
from app.investigation.iocs_repo import get_iocs, save_iocs
from app.ioc.extractor import extract_iocs
from app.main import app
from app.schemas.dns_record import DnsRecord
from app.schemas.flow import Flow
from app.schemas.host import Host
from app.schemas.http_record import HttpRecord
from fastapi.testclient import TestClient


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


START = datetime(2024, 1, 1, tzinfo=UTC)


def add_investigation(investigation_id: str = "investigation-1") -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (investigation_id, "sample.pcap", "pcap", 1, "aggregated", START.isoformat()),
        )


def make_host(host_id: str, ip: str, offset: int = 0) -> Host:
    timestamp = START + timedelta(seconds=offset)
    return Host(
        id=host_id,
        investigation_id="investigation-1",
        ip=ip,
        scope="internal",
        packets_sent=1,
        packets_received=0,
        bytes_sent=100,
        bytes_received=0,
        unique_destinations=1,
        unique_ports=1,
        first_seen=timestamp.isoformat(),
        last_seen=timestamp.isoformat(),
    )


def make_flow(flow_id: str, src_ip: str, dst_ip: str, offset: int = 0) -> Flow:
    timestamp = START + timedelta(seconds=offset)
    return Flow(
        id=flow_id,
        investigation_id="investigation-1",
        src_ip=src_ip,
        src_port=50000,
        dst_ip=dst_ip,
        dst_port=443,
        protocol="TCP",
        packets_sent=1,
        packets_received=1,
        bytes_sent=100,
        bytes_received=100,
        first_seen=timestamp.isoformat(),
        last_seen=timestamp.isoformat(),
    )


def make_dns(record_id: str, query: str, offset: int = 0) -> DnsRecord:
    timestamp = START + timedelta(seconds=offset)
    return DnsRecord(
        id=record_id,
        investigation_id="investigation-1",
        timestamp=timestamp.isoformat(),
        source_ip="10.0.0.5",
        destination_ip="8.8.8.8",
        query=query,
        query_type="A",
        response_code=0,
        answers=["93.184.216.34"],
    )


def make_http(
    record_id: str,
    host: str | None = "Example.COM",
    path: str | None = "/index.html",
    user_agent: str | None = "Mozilla/5.0",
    destination_port: int = 443,
    offset: int = 0,
) -> HttpRecord:
    timestamp = START + timedelta(seconds=offset)
    return HttpRecord(
        id=record_id,
        investigation_id="investigation-1",
        timestamp=timestamp.isoformat(),
        source_ip="10.0.0.5",
        source_port=50000,
        destination_ip="93.184.216.34",
        destination_port=destination_port,
        method="GET",
        host=host,
        path=path,
        user_agent=user_agent,
        status_code=200,
    )


def extract_with(
    *,
    hosts: list[Host] | None = None,
    flows: list[Flow] | None = None,
    dns_records: list[DnsRecord] | None = None,
    http_records: list[HttpRecord] | None = None,
):
    add_investigation()
    with get_connection() as conn:
        save_hosts(conn, "investigation-1", hosts or [])
        save_flows(conn, "investigation-1", flows or [])
        save_dns_records(conn, "investigation-1", dns_records or [])
        save_http_records(conn, "investigation-1", http_records or [])
        return extract_iocs(conn, "investigation-1")


def find_ioc(iocs, ioc_type: str, value: str):
    return next(ioc for ioc in iocs if ioc.ioc_type == ioc_type and ioc.value == value)


def test_extract_ipv4_from_hosts():
    iocs = extract_with(hosts=[make_host("host-1", "10.0.0.5")])

    ioc = find_ioc(iocs, "ipv4", "10.0.0.5")
    assert ioc.occurrences == 1
    assert ioc.evidence_type == "host"
    assert ioc.evidence_ids == ["host-1"]


def test_extract_ipv6_from_flows():
    iocs = extract_with(flows=[make_flow("flow-1", "2001:db8::1", "2001:db8::2")])

    values = {ioc.value for ioc in iocs if ioc.ioc_type == "ipv6"}
    assert values == {"2001:db8::1", "2001:db8::2"}


def test_extract_domains_from_dns():
    iocs = extract_with(dns_records=[make_dns("dns-1", "WWW.Example.COM.")])

    assert find_ioc(iocs, "domain", "www.example.com").evidence_type == "dns"


def test_evidence_type_is_mixed_when_sources_differ():
    iocs = extract_with(
        dns_records=[make_dns("dns-1", "example.com")],
        http_records=[make_http("http-1", host="example.com")],
    )

    ioc = find_ioc(iocs, "domain", "example.com")
    assert ioc.evidence_type == "mixed"
    assert ioc.occurrences >= 2


def test_evidence_type_single_source():
    iocs = extract_with(dns_records=[make_dns("dns-1", "example.com")])

    assert find_ioc(iocs, "domain", "example.com").evidence_type == "dns"


def test_extract_domains_from_http_host():
    iocs = extract_with(http_records=[make_http("http-1", host="WWW.Example.COM")])

    assert find_ioc(iocs, "domain", "www.example.com").evidence_type == "http"


def test_extract_urls_from_http():
    iocs = extract_with(
        http_records=[
            make_http("http-1", host="example.com", path="/login", destination_port=443),
            make_http("http-2", host="example.com", path="/status", destination_port=80),
        ]
    )

    assert {ioc.value for ioc in iocs if ioc.ioc_type == "url"} == {
        "https://example.com/login",
        "http://example.com/status",
    }


def test_extract_user_agents():
    iocs = extract_with(http_records=[make_http("http-1", user_agent="curl/8.0")])

    assert find_ioc(iocs, "user_agent", "curl/8.0").occurrences == 1


def test_deduplication_merges_occurrences():
    iocs = extract_with(
        hosts=[make_host("host-1", "10.0.0.5", 0)],
        flows=[make_flow("flow-1", "10.0.0.5", "8.8.8.8", 1)],
        dns_records=[make_dns("dns-1", "example.com", 2)],
        http_records=[make_http("http-1", host="EXAMPLE.COM", offset=3)],
    )

    ip_ioc = find_ioc(iocs, "ipv4", "10.0.0.5")
    domain_ioc = find_ioc(iocs, "domain", "example.com")
    assert ip_ioc.occurrences == 2
    assert domain_ioc.occurrences == 2
    assert ip_ioc.first_seen == START.isoformat()
    assert ip_ioc.last_seen == (START + timedelta(seconds=1)).isoformat()
    assert set(ip_ioc.evidence_ids) == {"host-1", "flow-1"}


def test_scope_classification():
    iocs = extract_with(hosts=[make_host("internal", "10.0.0.5"), make_host("external", "8.8.8.8")])

    assert find_ioc(iocs, "ipv4", "10.0.0.5").scope == "internal"
    assert find_ioc(iocs, "ipv4", "8.8.8.8").scope == "external"


def test_extract_skips_malformed_data():
    add_investigation()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO hosts (id, investigation_id, ip, scope, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("bad", "investigation-1", "10.0.0.5", "internal", "bad", "bad"),
        )
        assert extract_iocs(conn, "investigation-1") == []


def test_save_iocs_is_idempotent():
    iocs = extract_with(hosts=[make_host("host-1", "10.0.0.5")])

    with get_connection() as conn:
        save_iocs(conn, "investigation-1", iocs)
        save_iocs(conn, "investigation-1", iocs)
        saved = get_iocs(conn, "investigation-1")

    assert len(saved) == len(iocs)
    assert saved[0].value == "10.0.0.5"


def test_iocs_endpoint_returns_empty_for_existing():
    add_investigation()

    with TestClient(app) as client:
        response = client.get("/api/investigations/investigation-1/iocs")

    assert response.status_code == 200
    assert response.json() == []


def test_iocs_endpoint_returns_404_for_missing():
    with TestClient(app) as client:
        response = client.get("/api/investigations/missing/iocs")

    assert response.status_code == 404


def test_upload_returns_aggregated_with_iocs():
    with TestClient(app) as client, Path("data/samples/http.pcap").open("rb") as capture:
        upload_response = client.post(
            "/api/investigations",
            files={"file": ("http.pcap", io.BytesIO(capture.read()), "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        investigation = upload_response.json()
        assert investigation["status"] == "aggregated"
        iocs_response = client.get(f"/api/investigations/{investigation['id']}/iocs")

    assert iocs_response.status_code == 200
    iocs = iocs_response.json()
    assert any(item["ioc_type"] == "domain" for item in iocs)
    assert any(item["ioc_type"] in {"ipv4", "ipv6"} for item in iocs)
