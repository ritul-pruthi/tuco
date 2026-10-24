import sqlite3
from pathlib import Path

import pytest
from app.ai.schemas import AiReportRecord
from app.core import config
from app.core.db import get_connection, init_db
from app.investigation.ai_reports_repo import (
    get_latest_ai_report,
    list_ai_reports_for_investigation,
    save_ai_report,
)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "reports.db")
    init_db()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations
            (id, filename, format, size_bytes, packet_count, started_at, ended_at,
             duration_seconds, status, created_at)
            VALUES ('inv-1', 'capture.pcap', 'pcap', 1, 0, NULL, NULL, NULL,
                    'aggregated', '2026-01-01T00:00:00Z')
            """
        )
        conn.commit()
        yield conn


def save_sample(conn: sqlite3.Connection, investigation_id: str = "inv-1") -> str:
    return save_ai_report(
        conn,
        investigation_id,
        "test-model",
        "v5",
        {"summary": "分析", "nested": {"items": [1, "é"]}},
        "## Summary\n分析",
        [{"type": "note", "value": "é"}],
    )


def test_save_returns_hex_id_and_round_trips_record(db: sqlite3.Connection):
    report_id = save_sample(db)
    assert len(report_id) == 32
    assert all(character in "0123456789abcdef" for character in report_id)

    records = list_ai_reports_for_investigation(db, "inv-1")
    assert len(records) == 1
    assert records[0] == AiReportRecord(
        id=report_id,
        investigation_id="inv-1",
        model="test-model",
        prompt_version="v5",
        report={"summary": "分析", "nested": {"items": [1, "é"]}},
        markdown="## Summary\n分析",
        warnings=[{"type": "note", "value": "é"}],
        created_at=records[0].created_at,
    )


def test_latest_returns_newest_by_created_at(db: sqlite3.Connection):
    first = save_sample(db)
    second = save_sample(db)
    db.execute(
        "UPDATE ai_reports SET created_at = ? WHERE id = ?",
        ("2026-01-01T00:00:01+00:00", first),
    )
    db.execute(
        "UPDATE ai_reports SET created_at = ? WHERE id = ?",
        ("2026-01-01T00:00:02+00:00", second),
    )
    db.commit()

    assert get_latest_ai_report(db, "inv-1").id == second


def test_latest_returns_none_without_reports(db: sqlite3.Connection):
    assert get_latest_ai_report(db, "inv-1") is None


def test_listing_orders_newest_first(db: sqlite3.Connection):
    report_ids = [save_sample(db) for _ in range(3)]
    for index, report_id in enumerate(report_ids):
        db.execute(
            "UPDATE ai_reports SET created_at = ? WHERE id = ?",
            (f"2026-01-01T00:00:0{index}+00:00", report_id),
        )
    db.commit()

    assert [record.id for record in list_ai_reports_for_investigation(db, "inv-1")] == [
        report_ids[2],
        report_ids[1],
        report_ids[0],
    ]


def test_unknown_investigation_returns_empty_list(db: sqlite3.Connection):
    assert list_ai_reports_for_investigation(db, "missing") == []
