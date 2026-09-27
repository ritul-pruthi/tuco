import shutil
import uuid
from pathlib import Path

from app.core import config
from fastapi import HTTPException, UploadFile

CHUNK_SIZE = 1024 * 1024  # 1 MB


def save_upload(file: UploadFile) -> tuple[Path, str, str]:
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file must have a valid filename.",
        )

    ext = Path(file.filename).suffix.lower()
    if ext not in config.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file extension. Allowed extensions are: {', '.join(sorted(config.ALLOWED_EXTENSIONS))}",
        )

    first_bytes = file.file.read(4)
    if len(first_bytes) < 4 or first_bytes not in config.PCAP_MAGIC_BYTES:
        raise HTTPException(
            status_code=400,
            detail="Invalid PCAP file header magic bytes.",
        )

    format_string = "pcapng" if first_bytes == b"\x0a\x0d\x0d\x0a" else "pcap"

    internal_filename = f"{uuid.uuid4().hex}{ext}"
    temp_path = Path(config.TMP_DIR) / internal_filename
    final_path = Path(config.UPLOAD_DIR) / internal_filename

    Path(config.TMP_DIR).mkdir(parents=True, exist_ok=True)
    Path(config.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

    total_bytes = len(first_bytes)
    if total_bytes > config.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds maximum allowed size of {config.MAX_UPLOAD_BYTES} bytes.",
        )

    try:
        with open(temp_path, "wb") as dest:
            dest.write(first_bytes)
            while True:
                chunk = file.file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds maximum allowed size of {config.MAX_UPLOAD_BYTES} bytes.",
                    )
                dest.write(chunk)

        shutil.move(str(temp_path), str(final_path))
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise

    return final_path, internal_filename, format_string
