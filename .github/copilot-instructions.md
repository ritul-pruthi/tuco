# TUCO — Instructions for GitHub Copilot

This file is your full context. Read it before responding to any request in this workspace.

---

## 1. What TUCO Is

TUCO is a SOC-focused network investigation workbench. It ingests `.pcap`/`.pcapng` files, extracts network facts (hosts, flows, DNS, HTTP, TLS metadata), runs deterministic detections, builds a timeline and IOC set, and exposes everything through an investigation API and UI.

**It is NOT a Wireshark replacement. It is NOT an autonomous threat hunter. It is NOT an AI-based malware detector.**

Core principle from PRD.md: "The investigation is the product. The PCAP is the evidence."

---

## 2. Current Phase and Task

Read `docs/internal/MEMORY.md` for the authoritative state: which phase we are in, which sub-tasks are complete, which is next.

Do not start a later sub-task or phase without explicit instruction.

---

## 3. Rules You Must Follow

### Evidence

1. Separate observation from interpretation.
2. Every detection has supporting evidence.
3. Never claim certainty beyond available evidence.
4. Heuristics do not prove compromise or malware.
5. Preserve timestamp and source/destination context.
6. Never fabricate missing protocol information.

### Detection

1. Thresholds are deterministic and documented.
2. Every detector explains why it triggered.
3. Detector output is structured, not UI-specific.
4. Do not use an LLM as the Phase 1 detection engine.
5. Reputation is not proof of compromise.

### Development

- Read project docs before coding.
- Work phase-by-phase.
- Inspect existing code before modifying it.
- Test meaningful changes.
- Fix regressions before proceeding.
- Keep dependencies justified.
- Keep secrets out of source control.
- Update MEMORY.md after meaningful sessions.
- If a command is interactive, use a non-interactive flag or skip it and report the exact command for the user to run manually.

### UI

No purple gradients, glassmorphism, pill-shaped controls, fake metrics, or stock AI imagery. TUCO should feel like professional security software.

---

## 4. Architecture

PCAP → Secure Ingestion → Packet Parser → Normalization
→ Hosts / Flows / DNS / HTTP / TLS → Evidence Store
→ Detection Engine + Timeline + IOC Extraction
→ Investigation API → Web UI

text

Key rules: separate parsing/normalization/detection/investigation/presentation; Phase 1 works without AI; every higher-level finding traces to evidence; uploaded PCAPs are untrusted; components should be replaceable.

---

## 5. Tech Stack

- **Backend:** Python 3.14, FastAPI, Pydantic, Scapy 2.7.0, Uvicorn, sqlite3 (stdlib, no ORM).
- **Frontend:** React + TypeScript + Vite.
- **Testing:** pytest (backend), vitest (frontend).
- **Linting:** ruff (backend), eslint (frontend).
- **Virtualenv:** `.venv/` at repo root. Invoke as `.venv/bin/python`.

---

## 6. Repository Structure

tuco/
├── backend/app/
│ ├── api/ → FastAPI routers
│ ├── core/ → config, db, storage, scope
│ ├── schemas/ → Pydantic models
│ ├── parsers/ → pcap_parser, host_aggregator, flow_aggregator, dns_extractor, http_extractor
│ ├── detections/ → base, config, registry, port_scan, internal_recon, beacon
│ ├── investigation/ → repos: hosts, flows, dns, http, detections
│ ├── ioc/ → (empty, Phase 1)
│ └── ai/ → (empty, Phase 2)
├── backend/tests/
├── frontend/
├── data/samples/
├── data/uploads/ → UUID-named uploads (gitignored)
├── docs/internal/ → private docs (gitignored)
└── pyproject.toml

text

---

## 7. Data Model

- **Investigation:** id, filename, format, size, packet count, start/end, duration, status.
- **Host:** id, IP, MAC, scope, packets/bytes sent/received, first/last seen.
- **Flow:** id, source/destination IP and port, protocol, packets, bytes, first/last seen, TCP state.
- **DNS record:** timestamp, source/destination, query, type, response code, answers.
- **Detection:** id, rule ID, title, severity, confidence, timeframe, source/destination, explanation, evidence references, limitations.
- **Timeline event:** timestamp, type, source, destination, summary, evidence references.

Use `model_config = ConfigDict(from_attributes=True)` for schemas tied to DB rows.

---

## 8. API Convention

POST /api/investigations
GET /api/investigations/{id}
GET /api/investigations/{id}/hosts
GET /api/investigations/{id}/flows
GET /api/investigations/{id}/dns
GET /api/investigations/{id}/http
GET /api/investigations/{id}/tls
GET /api/investigations/{id}/detections
GET /api/investigations/{id}/timeline
GET /api/investigations/{id}/iocs

text

Every new read endpoint: return 404 if investigation missing, empty list if no records, Pydantic response model.

---

## 9. Coding Conventions

- Parse PCAPs by streaming (`PcapReader`/`PcapNgReader`, never `rdpcap`).
- Reuse reader selection from `pcap_parser.py`.
- Repository pattern: sqlite3 code lives in `backend/app/investigation/*_repo.py`.
- Idempotent saves: delete existing rows before insert.
- Status transitions: `uploaded` → `parsed` → `aggregated` → `failed`. Keep files on failure.
- Never use user filenames for filesystem paths. Always UUID.
- Type hints everywhere.
- Sync, not async, for endpoints that do file I/O.

---

## 10. Testing Requirements

Tests cover: happy path, malformed input, empty capture, idempotency (if save function exists).

Tests use temp SQLite DB and temp dirs via monkeypatching `config.DB_PATH`, `config.UPLOAD_DIR`, `config.TMP_DIR`.

Before claiming success, run:

```bash
.venv/bin/python -m pytest backend/tests/ -v
.venv/bin/ruff check backend/
Report exact output. Never say "tests pass" without showing it.

11. What You Must NOT Do
Invent requirements or features not in the docs.

Start a later sub-task or phase without instruction.

Replace deterministic logic with an LLM.

Claim untested functionality works.

Redesign the product without instruction.

Modify detection thresholds without updating docs.

Add dependencies without justification.

Fabricate data (MAC addresses come from ARP only).

Write stub tests.

Touch frontend/ for backend-only tasks, or vice versa.

Commit anything. The user commits.

12. Workflow
Read MEMORY.md for current state.

Read specific docs for the task.

Implement only what the task asks.

Write tests.

Run tests and ruff. Fix failures.

Run a manual curl test where applicable.

Report exact output.

Update MEMORY.md (see section 16).

Stop. Do not commit.

13. Commit Style
Short, present-tense, human. Examples:

Add DNS extraction

Add HTTP extraction

Add beacon detector

Not: "Phase 1, sub-task N: implement ..."

14. Communication Style
Direct. Short answers beat long ones. Explain technical terms in plain language. Do not over-explain basics. If something is wrong, say so. If uncertain, say so. Do not suggest large refactors. Stay scoped.

15. If a Command Is Interactive
Skip it and tell the user the exact command to run manually. Examples: npm create vite@latest, gh auth login.

16. After Completing Any Sub-Task
When a sub-task is done and tests + lint pass:

Update docs/internal/MEMORY.md:

Check off the completed sub-task in ## Phase 1 Progress

Update ## Next Task to the next unchecked sub-task with one-line scope

Add a Change Log entry under the current version (bump minor version)

Report the exact MEMORY.md changes in your summary

Do NOT commit — the user commits

Never finish a sub-task without updating MEMORY.md. This overrides any prompt instruction to the contrary.

End of instructions. When in doubt, read docs/internal/.
ENDOFFILE

```
