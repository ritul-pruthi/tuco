# TUCO — Instructions for GitHub Copilot

This file is your full context. Read it before responding to any request in this workspace.

---

## 1. What TUCO Is

TUCO is a SOC-focused network investigation workbench. It ingests `.pcap`/`.pcapng` files, extracts network facts (hosts, flows, DNS, HTTP, TLS metadata), runs deterministic detections, builds a timeline and IOC set, and exposes everything through an investigation API and UI.

**It is NOT a Wireshark replacement. It is NOT an autonomous threat hunter. It is NOT an AI-based malware detector.**

Core principle from PRD.md: "The investigation is the product. The PCAP is the evidence."

---

## 2. Current Phase and Task

Read `docs/internal/MEMORY.md` for the authoritative state:

- Which phase we are in
- Which sub-tasks are complete
- Which sub-task is next

Do not start a later sub-task or phase without explicit instruction.

---

## 3. Rules You Must Follow

Copied from `docs/internal/RULES.md`:

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

Read `docs/internal/ARCHITECTURE.md` for the full picture. Summary:
PCAP → Secure Ingestion → Packet Parser → Normalization
→ Hosts / Flows / DNS / HTTP / TLS → Evidence Store
→ Detection Engine + Timeline + IOC Extraction
→ Investigation API → Web UI

text

Key rules:

- Separate parsing, normalization, detection, investigation, presentation.
- Phase 1 works without AI.
- Every higher-level finding traces to evidence.
- Uploaded PCAPs are untrusted.
- Components should be replaceable.

---

## 5. Tech Stack

- **Backend:** Python 3.14, FastAPI, Pydantic, Scapy 2.7.0, Uvicorn, sqlite3 (stdlib, **no ORM**).
- **Frontend:** React + TypeScript + Vite.
- **Testing:** pytest (backend), vitest (frontend).
- **Linting:** ruff (backend), eslint (frontend).
- **Virtualenv:** `.venv/` at repo root. Always invoke as `.venv/bin/python` — do not assume activation.

---

## 6. Repository Structure

tuco/
├── backend/app/
│ ├── api/ → FastAPI routers (investigations.py)
│ ├── core/ → config.py, db.py, storage.py, scope.py
│ ├── models/ → (empty, Phase 1+)
│ ├── schemas/ → Pydantic models (investigation, pcap*summary, host, flow, dns_record)
│ ├── parsers/ → pcap_parser.py, host_aggregator.py, flow_aggregator.py, dns_extractor.py
│ ├── normalization/ → (empty)
│ ├── detections/ → (empty, Phase 1 late)
│ ├── investigation/ → repos: hosts_repo, flows_repo, dns_repo
│ ├── ioc/ → (empty, Phase 1)
│ └── ai/ → (empty, Phase 2)
├── backend/tests/ → test*\*.py
├── frontend/ → React + Vite
├── data/samples/ → sample PCAPs for manual tests
├── data/uploads/ → app writes UUID-named uploads here (gitignored)
├── docs/internal/ → private planning docs (gitignored)
└── pyproject.toml

text

---

## 7. Data Model (from ARCHITECTURE.md §6)

- **Investigation:** id, filename, format, size, packet count, start/end, duration, status.
- **Host:** id, IP, MAC, scope, packets/bytes sent/received, first/last seen.
- **Flow:** id, source/destination IP and port, protocol, packets, bytes, first/last seen, TCP state.
- **DNS record:** timestamp, source/destination, query, type, response code, answers.
- **Detection:** id, rule ID, title, severity, confidence, timeframe, source/destination, explanation, evidence references, limitations.
- **Timeline event:** timestamp, type, source, destination, summary, evidence references.

When adding a new schema, follow the existing style — `model_config = ConfigDict(from_attributes=True)` for schemas tied to DB rows.

---

## 8. API Convention

POST /api/investigations → upload PCAP
GET /api/investigations/{id} → investigation metadata
GET /api/investigations/{id}/hosts → host list
GET /api/investigations/{id}/flows → flow list
GET /api/investigations/{id}/dns → DNS records
GET /api/investigations/{id}/http → HTTP records
GET /api/investigations/{id}/tls → TLS records
GET /api/investigations/{id}/detections → detections
GET /api/investigations/{id}/timeline → timeline
GET /api/investigations/{id}/iocs → IOCs

text

Every new read endpoint must:

- Return 404 if the investigation does not exist.
- Return an empty list if it exists but has no records yet.
- Return a Pydantic response model.

---

## 9. Coding Conventions

- **Parse PCAPs by streaming.** Use `PcapReader` / `PcapNgReader`, never `rdpcap`.
- **Reuse reader selection.** `pcap_parser.py` decides `PcapReader` vs `PcapNgReader`. Import that logic instead of duplicating.
- **Repository pattern for DB access.** All sqlite3 code lives in `backend/app/investigation/*_repo.py`. API handlers call repo functions.
- **Idempotent saves.** `save_*` functions delete existing rows for the investigation before inserting. Running twice produces the same result.
- **Status transitions.** Investigation status goes: `uploaded` → `parsed` → `aggregated` → `failed`. On any parsing/aggregation failure, set `failed` and keep the file for debugging.
- **Never use user filenames for filesystem paths.** Always UUID.
- **Type hints everywhere.** `str | None`, `list[Flow]`, etc.
- **Sync, not async**, for endpoints that do file I/O. FastAPI runs sync endpoints in a threadpool.

---

## 10. Testing Requirements

Every sub-task must add tests for:

- Positive case (happy path).
- Negative case (malformed input, missing file, wrong format).
- Empty capture.
- Idempotency (if there's a save function).

Tests use a temp SQLite DB and temp directories via monkeypatching `config.DB_PATH`, `config.UPLOAD_DIR`, `config.TMP_DIR`.

Run before claiming success:

```bash
.venv/bin/python -m pytest backend/tests/ -v
.venv/bin/ruff check backend/
Report exact output. Never say "tests pass" without showing the output.

11. What You Must NOT Do
Invent requirements or add features not in the docs.

Start a later sub-task or phase without explicit instruction.

Replace deterministic logic with an LLM.

Claim untested functionality works.

Redesign the product, UI, or architecture without explicit instruction.

Modify detection thresholds or logic without updating the relevant docs.

Add dependencies without justification.

Fabricate data (e.g., MAC addresses from Ethernet for external IPs — MACs come from ARP only).

Write stub tests that pass trivially.

Touch frontend/ when the task is backend-only, or vice versa.

Commit anything. The user commits.

12. Workflow
For each sub-task:

Read MEMORY.md for current state.

Read the specific docs relevant to the task.

Implement only what the task asks.

Write tests.

Run tests and ruff. Fix failures.

Run a manual curl test where applicable.

Report exact output.

Stop. Do not commit. Do not update MEMORY.md unless told.

13. Commit Style
Short, present-tense, human. Examples from the actual repo history:

Initial commit: project documentation and license

Add backend scaffold

Add upload endpoint

Add PCAP parser

Add host aggregation

Add flow aggregation

Add DNS extraction (next)

Not: "Phase 1, sub-task 5: implement DNS extraction logic with parsing and persistence"
Yes: "Add DNS extraction"

14. Communication Style with the User
Be direct. Short answers beat long ones.

Explain technical terms in plain language when introducing them.

Do not over-explain basics (the user has built this much).

If something is wrong, say so clearly and explain why.

If you are uncertain, say so — do not guess.

Do not suggest large refactors.

Stay scoped to the current sub-task.

15. If a Command Is Interactive
Skip it and tell the user the exact command to run manually. Examples:

npm create vite@latest — interactive prompt, may hang.

gh auth login — browser-based, must be done by the user.

End of instructions. When in doubt, read the actual docs in docs/internal/.
ENDOFFILE



```
