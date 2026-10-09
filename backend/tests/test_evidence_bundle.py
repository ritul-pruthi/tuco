import json
import sqlite3
from pathlib import Path

import pytest
from app.ai.evidence_bundle import MAX_HOSTS, MAX_TIMELINE_EVENTS, build_evidence_bundle
from app.core import config
from app.core.db import get_connection, init_db


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "bundle.db")
    init_db()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations
            (id, filename, format, size_bytes, packet_count, started_at, ended_at,
             duration_seconds, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "inv-1",
                "capture.pcap",
                "pcap",
                1234,
                10,
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:01:00Z",
                60.0,
                "aggregated",
                "2026-01-01T00:02:00Z",
            ),
        )
        conn.commit()
        yield conn


def insert_host(conn: sqlite3.Connection, host_id: str, ip: str, bytes_sent: int = 10):
    conn.execute(
        """
        INSERT INTO hosts
        (id, investigation_id, ip, mac, scope, packets_sent, packets_received,
         bytes_sent, bytes_received, unique_destinations, unique_ports, first_seen, last_seen)
        VALUES (?, 'inv-1', ?, NULL, ?, 1, 2, ?, 20, 3, 4, ?, ?)
        """,
        (
            host_id,
            ip,
            "internal" if ip.startswith("10.") else "external",
            bytes_sent,
            "2026-01-01T00:00:01Z",
            "2026-01-01T00:00:59Z",
        ),
    )


def insert_flow(conn: sqlite3.Connection, flow_id: str, tcp_state: str | None):
    conn.execute(
        """
        INSERT INTO flows
        (id, investigation_id, src_ip, src_port, dst_ip, dst_port, protocol,
         packets_sent, packets_received, bytes_sent, bytes_received, first_seen, last_seen, tcp_state)
        VALUES (?, 'inv-1', '10.0.0.1', 1234, '8.8.8.8', 443, 'TCP',
                2, 1, 100, 50, '', '2026-01-01T00:00:10Z', ?)
        """,
        (flow_id, tcp_state),
    )


def test_builds_populated_deterministic_json_bundle(db: sqlite3.Connection):
    insert_host(db, "host-1", "10.0.0.1", 100)
    insert_host(db, "host-2", "8.8.8.8", 50)
    insert_flow(db, "flow-1", None)
    db.execute(
        """
        INSERT INTO dns_records
        (id, investigation_id, timestamp, source_ip, destination_ip, query, query_type, response_code, answers)
        VALUES ('dns-1', 'inv-1', '2026-01-01T00:00:02Z', '10.0.0.1', '8.8.8.8',
                'example.com', 'A', 0, '[]')
        """
    )
    db.execute(
        """
        INSERT INTO http_records
        (id, investigation_id, timestamp, source_ip, source_port, destination_ip,
         destination_port, method, host, path, user_agent, status_code)
        VALUES ('http-1', 'inv-1', '2026-01-01T00:00:03Z', '10.0.0.1', 1234,
                '8.8.8.8', 80, 'GET', 'example.com', '/', 'test-agent', 200)
        """
    )
    db.execute(
        """
        INSERT INTO tls_records
        (id, investigation_id, timestamp, source_ip, source_port, destination_ip,
         destination_port, sni, tls_version, certificate_subject, certificate_issuer,
         certificate_not_before, certificate_not_after)
        VALUES ('tls-1', 'inv-1', '2026-01-01T00:00:04Z', '10.0.0.1', 1234,
                '8.8.8.8', 443, 'example.com', 'TLSv1.3', NULL, NULL, NULL, NULL)
        """
    )
    db.execute(
        """
        INSERT INTO detections
        (id, investigation_id, rule_id, title, severity, confidence, source_ip, source_port,
         destination_ip, destination_port, timeframe_start, timeframe_end, observed_metric,
         observed_value, threshold_description, threshold_value, explanation, evidence,
         limitations, created_at)
        VALUES ('det-1', 'inv-1', 'port_scan_v1', 'Port scan', 'medium', 'high', '10.0.0.1',
                NULL, '8.8.8.8', NULL, '2026-01-01T00:00:01Z', '2026-01-01T00:00:05Z',
                'ports', 5, 'more than 3', 3, 'Observed multiple ports', '[{"id":"flow-1"}]',
                'Does not prove compromise', '2026-01-01T00:00:05Z')
        """
    )
    db.execute(
        """
        INSERT INTO iocs
        (id, investigation_id, ioc_type, value, first_seen, last_seen, occurrences,
         scope, evidence_type, evidence_ids)
        VALUES ('ioc-1', 'inv-1', 'domain', 'example.com', '2026-01-01T00:00:02Z',
                '2026-01-01T00:00:04Z', 2, 'external', 'dns', '["dns-1"]')
        """
    )
    db.execute(
        """
        INSERT INTO timeline_events
        (id, investigation_id, timestamp, event_type, source, destination, summary,
         evidence_type, evidence_id)
        VALUES ('event-1', 'inv-1', '2026-01-01T00:00:05Z', 'detection', '10.0.0.1',
                '8.8.8.8', 'Port scan detected', 'detection', 'det-1')
        """
    )
    db.commit()

    bundle = build_evidence_bundle(db, "inv-1")
    assert list(bundle) == [
        "investigation",
        "summary",
        "hosts",
        "flows",
        "detections",
        "mitre_techniques",
        "dns",
        "http",
        "tls",
        "observables",
        "timeline_highlights",
        "limits",
    ]
    assert bundle["summary"]["host_count"] == 2
    assert bundle["hosts"][0]["ip"] == "10.0.0.1"
    assert "mac" not in bundle["hosts"][0]
    assert bundle["flows"][0]["tcp_state"] is None
    assert bundle["flows"][0]["first_seen"] == ""
    assert bundle["detections"][0]["evidence_count"] == 1
    assert "evidence" not in bundle["detections"][0]
    assert bundle["detections"][0]["mitre_techniques"] == [
        {"id": "T1046", "name": "Network Service Discovery"}
    ]
    assert bundle["mitre_techniques"][0]["rule_ids"] == ["port_scan_v1"]
    assert bundle["dns"]["top_queries"] == [{"query": "example.com", "query_type": "A", "count": 1}]
    assert bundle["http"]["method_counts"] == {"GET": 1}
    assert bundle["tls"]["tls_version_counts"] == {"TLSv1.3": 1}
    assert json.dumps(bundle)
    assert bundle == build_evidence_bundle(db, "inv-1")


def test_missing_investigation_raises_value_error(db: sqlite3.Connection):
    with pytest.raises(ValueError, match="Investigation not found"):
        build_evidence_bundle(db, "missing")


def test_empty_investigation_returns_empty_sections(db: sqlite3.Connection):
    bundle = build_evidence_bundle(db, "inv-1")
    assert all(
        bundle[key] == []
        for key in (
            "hosts",
            "flows",
            "detections",
            "mitre_techniques",
            "observables",
            "timeline_highlights",
        )
    )
    assert all(value == 0 for value in bundle["summary"].values())
    assert all(value is False for value in bundle["limits"].values())


def test_unknown_detection_rule_has_no_techniques(db: sqlite3.Connection):
    db.execute(
        """
        INSERT INTO detections
        (id, investigation_id, rule_id, title, severity, confidence, source_ip, source_port,
         destination_ip, destination_port, timeframe_start, timeframe_end, observed_metric,
         observed_value, threshold_description, threshold_value, explanation, evidence,
         limitations, created_at)
        VALUES ('det-unknown', 'inv-1', 'unknown_v1', 'Unknown', 'low', 'low', '10.0.0.1',
                NULL, '8.8.8.8', NULL, 'start', 'end', 'metric', 1, 'threshold', 1,
                'Observed', '[]', 'Limited', 'created')
        """
    )
    db.commit()
    bundle = build_evidence_bundle(db, "inv-1")
    assert bundle["detections"][0]["mitre_techniques"] == []
    assert bundle["mitre_techniques"] == []


def test_hosts_and_timeline_are_bounded_without_dropping_detections(db: sqlite3.Connection):
    for index in range(200):
        insert_host(db, f"host-{index}", f"10.0.0.{index + 1}", index)
    for index in range(MAX_TIMELINE_EVENTS + 10):
        db.execute(
            """
            INSERT INTO timeline_events
            (id, investigation_id, timestamp, event_type, source, destination, summary,
             evidence_type, evidence_id)
            VALUES (?, 'inv-1', ?, 'flow', '10.0.0.1', '8.8.8.8', ?, 'flow', ?)
            """,
            (f"event-{index}", f"2026-01-01T00:00:{index:02d}Z", f"event {index}", f"flow-{index}"),
        )
    db.commit()
    bundle = build_evidence_bundle(db, "inv-1")
    assert len(bundle["hosts"]) == MAX_HOSTS
    assert bundle["limits"]["hosts_truncated"] is True
    assert len(bundle["timeline_highlights"]) == MAX_TIMELINE_EVENTS
    assert bundle["limits"]["timeline_truncated"] is True
