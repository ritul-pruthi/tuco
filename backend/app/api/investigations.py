import uuid
from datetime import UTC, datetime
from typing import Annotated

from app.core.db import get_connection
from app.core.storage import save_upload
from app.schemas.investigation import InvestigationResponse
from fastapi import APIRouter, File, UploadFile

router = APIRouter()


@router.post("/investigations", response_model=InvestigationResponse, status_code=201)
def create_investigation(file: Annotated[UploadFile, File()]):
    final_path, _internal_filename, file_format = save_upload(file)
    try:
        size_bytes = final_path.stat().st_size
        inv_id = uuid.uuid4().hex
        created_at = datetime.now(UTC).isoformat()

        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO investigations (
                    id, filename, format, size_bytes, packet_count,
                    started_at, ended_at, duration_seconds, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    inv_id,
                    file.filename or "",
                    file_format,
                    size_bytes,
                    None,
                    None,
                    None,
                    None,
                    "uploaded",
                    created_at,
                ),
            )
            conn.commit()

        return InvestigationResponse(
            id=inv_id,
            filename=file.filename or "",
            format=file_format,
            size_bytes=size_bytes,
            packet_count=None,
            started_at=None,
            ended_at=None,
            duration_seconds=None,
            status="uploaded",
            created_at=created_at,
        )
    except Exception:
        if final_path.exists():
            try:
                final_path.unlink()
            except OSError:
                pass
        raise
