import json
import sqlite3
import uuid
from datetime import UTC, datetime

from app.ai.schemas import AiReportRecord


def save_ai_report(
    conn: sqlite3.Connection,
    investigation_id: str,
    model: str,
    prompt_version: str,
    report: dict,
    markdown: str,
    warnings: list[dict],
) -> str:
    report_id = uuid.uuid4().hex
    conn.execute(
        """
        INSERT INTO ai_reports (
            id, investigation_id, model, prompt_version, report_json,
            markdown, warnings_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report_id,
            investigation_id,
            model,
            prompt_version,
            json.dumps(report, sort_keys=True),
            markdown,
            json.dumps(warnings, sort_keys=True),
            datetime.now(UTC).isoformat(),
        ),
    )
    conn.commit()
    return report_id


def _record_from_row(row: sqlite3.Row) -> AiReportRecord:
    data = dict(row)
    data["report"] = json.loads(data.pop("report_json"))
    data["warnings"] = json.loads(data.pop("warnings_json"))
    return AiReportRecord.model_validate(data)


def list_ai_reports_for_investigation(
    conn: sqlite3.Connection, investigation_id: str
) -> list[AiReportRecord]:
    rows = conn.execute(
        """
        SELECT *
        FROM ai_reports
        WHERE investigation_id = ?
        ORDER BY created_at DESC, id DESC
        """,
        (investigation_id,),
    ).fetchall()
    return [_record_from_row(row) for row in rows]


def get_latest_ai_report(
    conn: sqlite3.Connection, investigation_id: str
) -> AiReportRecord | None:
    row = conn.execute(
        """
        SELECT *
        FROM ai_reports
        WHERE investigation_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (investigation_id,),
    ).fetchone()
    return _record_from_row(row) if row is not None else None
