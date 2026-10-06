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

Install the backend and frontend dependencies once:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
cd frontend && npm install && cd ..
```

Start both development services from the project root with one command:

```bash
./scripts/dev.sh
```

The script keeps the services as separate processes, shows logs from both
services, and forwards Ctrl+C to both processes before exiting. The frontend
is available at http://127.0.0.1:5173 and the backend is available at
http://127.0.0.1:8000. The backend health check is
http://127.0.0.1:8000/health.

The script starts Uvicorn with the repository root as its working directory,
so the backend resolves runtime paths to `data/tuco.db`, `data/uploads/`, and
`data/tmp/`. This command does not migrate or delete any existing data. If the
backend is started manually from another working directory, its existing
relative-path configuration can use a different `data/` directory; the
existing `frontend/data/` directory is preserved.

Run backend tests and lint separately when needed:

```bash
.venv/bin/python -m pytest backend/tests/ -v
.venv/bin/ruff check backend/
```

DNS records are exposed at `GET /api/investigations/{id}/dns`.
HTTP records are exposed at `GET /api/investigations/{id}/http`.
TLS metadata is exposed at `GET /api/investigations/{id}/tls`.
Detections are exposed at `GET /api/investigations/{id}/detections`.
IOCs are exposed at GET /api/investigations/{id}/iocs.
The investigation timeline is exposed at GET /api/investigations/{id}/timeline.
Investigations are listed at GET /api/investigations.
Investigation metadata is exposed at GET /api/investigations/{id}.

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
npm run test -- --run
npm run lint
npm run build
```

The one-command startup runs Vite for you. Open http://127.0.0.1:5173.
The backend must be running at http://127.0.0.1:8000. Upload a PCAP at `/` -
the app calls the backend and lists recent investigations.
Investigation detail views are available at `/investigations/{id}/hosts`, `/investigations/{id}/connections` (also `/flows`), `/investigations/{id}/dns`, `/investigations/{id}/http`, `/investigations/{id}/tls`, `/investigations/{id}/timeline`, and `/investigations/{id}/iocs`.

## License

MIT — see [LICENSE](LICENSE).
