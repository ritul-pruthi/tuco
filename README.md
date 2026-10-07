# TUCO

TUCO is a SOC-focused network investigation workbench for analyzing PCAP and
PCAPNG captures as evidence. It extracts network facts, stores structured
investigation data, runs deterministic detections, and provides an API and web
interface for tracing findings back to supporting evidence.

> The investigation is the product. The PCAP is the evidence.

TUCO is not a Wireshark replacement, an autonomous threat hunter, or a live
capture tool.

## What TUCO Does

TUCO processes an existing capture without executing packet contents. It
extracts hosts, flows, DNS, HTTP, TLS, observables, timeline events, and
deterministic detection results for investigation.

```text
PCAP → Parse → Normalize → Extract Evidence → Detect Patterns → Investigate
```

## Features

| Area | Details |
| --- | --- |
| Ingestion | Accepts PCAP/PCAPNG uploads, validates them, and records capture metadata. |
| Hosts | Aggregates IP, scope, traffic, port, timestamp, and available ARP-derived MAC data. |
| Flows | Aggregates bidirectional network flows with endpoints, protocol, counts, timestamps, and TCP state. |
| DNS | Extracts queries, types, response codes, answers, timestamps, and endpoints. |
| HTTP | Extracts visible methods, hosts, paths, status codes, user agents, timestamps, and endpoints. |
| TLS | Records available TLS version, SNI, certificate metadata, timestamps, and endpoints without decryption. |
| Detections | Runs six deterministic detectors with structured explanations and evidence references. |
| Observables | Extracts deduplicated IPs, domains, URLs, and user agents from parsed data. |
| Timeline | Builds a chronological event stream linked to hosts, protocol records, flows, and detections. |
| Web UI | Provides upload, investigation overview, evidence tables, detection details, filtering, and evidence navigation. |

## Detection Rules

| Rule ID | Firing condition |
| --- | --- |
| `port_scan_v1` | One source contacts at least 20 distinct destination ports on one target within 10 seconds. |
| `internal_recon_v1` | One internal source contacts at least 5 distinct internal targets within 30 seconds. |
| `beacon_v1` | At least 10 observations span at least 60 seconds and have an inter-arrival coefficient of variation at or below 0.20. |
| `dns_anomaly_v1` | A source produces at least 5 queries longer than 52 characters, at least 100 queries in 60 seconds, at least 20 distinct subdomains under one parent, or at least 10 failed responses. |
| `http_indicator_v1` | A source matches a tool-like user agent, accesses a suspicious path, or receives at least 20 HTTP error responses within 60 seconds. |
| `large_outbound_transfer_v1` | An internal source sends at least 10 MB in one flow to an external destination. |

Every detection carries severity, confidence, observed value, threshold,
explanation, evidence, and limitations.

## Tech Stack

| Layer | Technology |
| --- | --- |
| Backend | Python >= 3.11, FastAPI >= 0.110.0, Uvicorn >= 0.28.0 |
| Validation | Pydantic via FastAPI |
| Packet analysis | Scapy >= 2.5.0 |
| Cryptography | cryptography >= 42.0.0 |
| Storage | SQLite via Python's standard library |
| Frontend | React ^19.2.8, React DOM ^19.2.8, React Router ^7.18.4 |
| Frontend tooling | TypeScript ~6.0.2, Vite ^8.3.0, Vitest ^5.0.2, ESLint ^10.10.0 |

## Repository Structure

```text
tuco/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── detections/
│   │   ├── investigation/
│   │   ├── ioc/
│   │   ├── models/
│   │   ├── normalization/
│   │   ├── parsers/
│   │   └── schemas/
│   └── tests/
├── frontend/
│   └── src/
│       ├── assets/
│       ├── components/
│       ├── features/
│       ├── hooks/
│       ├── pages/
│       ├── services/
│       ├── styles/
│       └── types/
├── data/
├── scripts/
├── LICENSE
├── pyproject.toml
├── README.md
└── SECURITY.md
```

## Installation

Prerequisites:

- Python 3.11 or newer
- Node.js and npm

Clone the repository and install the backend package and frontend
dependencies:

```bash
git clone https://github.com/ritul-pruthi/tuco.git
cd tuco
python3 -m venv .venv
.venv/bin/pip install -e .
cd frontend
npm install
cd ..
```

## Running

Start the backend and frontend together from the repository root:

```bash
./scripts/dev.sh
```

To run the services manually, use two terminals:

```bash
.venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

```bash
cd frontend && npm run dev -- --host 127.0.0.1 --port 5173
```

| Service | URL |
| --- | --- |
| Web UI | http://127.0.0.1:5173 |
| Backend API | http://127.0.0.1:8000 |
| API docs | http://127.0.0.1:8000/docs |

## API Overview

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | Return backend health status. |
| `GET` | `/api/investigations` | List investigations with pagination metadata. |
| `POST` | `/api/investigations` | Upload and process a PCAP or PCAPNG capture. |
| `GET` | `/api/investigations/{investigation_id}` | Return investigation metadata and processing status. |
| `GET` | `/api/investigations/{investigation_id}/hosts` | Return aggregated hosts. |
| `GET` | `/api/investigations/{investigation_id}/flows` | Return aggregated network flows. |
| `GET` | `/api/investigations/{investigation_id}/dns` | Return extracted DNS records. |
| `GET` | `/api/investigations/{investigation_id}/http` | Return extracted HTTP records. |
| `GET` | `/api/investigations/{investigation_id}/tls` | Return extracted TLS metadata. |
| `GET` | `/api/investigations/{investigation_id}/detections` | Return deterministic detection results. |
| `GET` | `/api/investigations/{investigation_id}/iocs` | Return extracted observables. |
| `GET` | `/api/investigations/{investigation_id}/timeline` | Return chronological timeline events. |

Read endpoints return `404` when the investigation does not exist and an empty
list when it exists but has no records of the requested type.

## Testing

Backend:

```bash
.venv/bin/python -m pytest backend/tests/ -v
.venv/bin/ruff check backend/
```

Frontend:

```bash
cd frontend
npm run test -- --run
npm run lint
npm run build
```

## Design Principles

- Deterministic analysis comes before AI.
- Findings are backed by observed evidence and preserve source, destination, and timestamp context.
- Missing protocol information is never fabricated.
- Heuristics do not establish compromise or malware.
- Packet contents are analyzed as data and are never executed.
- PCAPs are untrusted input and are processed passively.
- The product is local-first and works without AI.

## Security

Uploaded captures are untrusted and may be malformed, maliciously crafted,
oversized, parser-stressing, or contain sensitive network data. TUCO validates
uploads, uses generated internal filenames and bounded local processing, and
does not execute captured files, payloads, or discovered URLs. Parser failures
and resource exhaustion are treated as security concerns, and future hosted
deployments require stronger isolation and access controls. See
[SECURITY.md](SECURITY.md) for the security requirements.

## Status

Phase 1 complete, Phase 2 planned.

## License

MIT — see [LICENSE](LICENSE).
