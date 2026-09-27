from pathlib import Path

UPLOAD_DIR = Path("data/uploads")
TMP_DIR = Path("data/tmp")
DB_PATH = Path("data/tuco.db")
MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGIC_BYTES = [
    b"\xa1\xb2\xc3\xd4",  # classic pcap, big-endian
    b"\xd4\xc3\xb2\xa1",  # classic pcap, little-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng
]

# Ensure data directories exist on import
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
