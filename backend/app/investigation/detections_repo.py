import json
import sqlite3

from app.schemas.detection import Detection


def save_detections(
    conn: sqlite3.Connection, investigation_id: str, detections: list[Detection]
) -> None:
    conn.execute("DELETE FROM detections WHERE investigation_id = ?", (investigation_id,))
    if detections:
        conn.executemany(
            """
            INSERT INTO detections (
                id, investigation_id, rule_id, title, severity, confidence,
                source_ip, source_port, destination_ip, destination_port,
                timeframe_start, timeframe_end, observed_metric, observed_value,
                threshold_description, threshold_value, explanation, evidence,
                limitations, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    detection.id,
                    detection.investigation_id,
                    detection.rule_id,
                    detection.title,
                    detection.severity,
                    detection.confidence,
                    detection.source_ip,
                    detection.source_port,
                    detection.destination_ip,
                    detection.destination_port,
                    detection.timeframe_start,
                    detection.timeframe_end,
                    detection.observed_metric,
                    detection.observed_value,
                    detection.threshold_description,
                    detection.threshold_value,
                    detection.explanation,
                    json.dumps(detection.evidence),
                    detection.limitations,
                    detection.created_at,
                )
                for detection in detections
            ],
        )
    conn.commit()


def get_detections(conn: sqlite3.Connection, investigation_id: str) -> list[Detection]:
    rows = conn.execute(
        "SELECT * FROM detections WHERE investigation_id = ? ORDER BY created_at ASC, id ASC",
        (investigation_id,),
    ).fetchall()
    detections = []
    for row in rows:
        data = dict(row)
        data["evidence"] = json.loads(data["evidence"])
        detections.append(Detection.model_validate(data))
    return detections
