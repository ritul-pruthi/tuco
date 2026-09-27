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

## License

MIT — see [LICENSE](LICENSE).