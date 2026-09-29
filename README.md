# TUCO

TUCO is a SOC-focused network investigation workbench that analyzes PCAP/PCAPNG captures as evidence.

It extracts hosts, flows, DNS, HTTP and TLS metadata, runs transparent detections, builds a timeline and IOC set, and helps analysts trace every finding back to the exact evidence that produced it.

TUCO is not a Wireshark replacement, autonomous threat hunter, or automatic malware detector.

## Status

Early development. See [SECURITY.md](SECURITY.md) for security requirements and [ARCHITECTURE.md](ARCHITECTURE.md) for design.

## Stack

- Backend: Python, FastAPI, Pydantic
- Frontend: React, TypeScript, Vite
- Storage: SQLite

## Backend

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
uvicorn app.main:app --app-dir backend --reload
python -m pytest backend/tests/ -v
```
DNS records are exposed at `GET /api/investigations/{id}/dns`.
HTTP records are exposed at `GET /api/investigations/{id}/http`.

### Upload Endpoint

To upload a capture for investigation, POST a `.pcap` or `.pcapng` file to `/api/investigations`:

```bash
curl -i -F "file=@/path/to/capture.pcap" http://localhost:8000/api/investigations
```

After upload, TUCO parses the capture and updates the investigation with packet count and time range.

After parsing, TUCO aggregates hosts and exposes them at GET /api/investigations/{id}/hosts.

Flows are exposed at GET /api/investigations/{id}/flows.


## Frontend

```bash
cd frontend
npm install
npm run dev
npm run test -- --run
```

## License

MIT — see [LICENSE](LICENSE).


