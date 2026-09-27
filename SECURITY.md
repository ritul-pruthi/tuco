# TUCO — Security Requirements

TUCO processes untrusted network captures. Security is a core requirement.

## Threat Model
Uploaded captures may be malformed, maliciously crafted, extremely large, parser-stressing, or contain exploit payloads, URLs, credentials or sensitive network data.

## Upload Security
- Validate extension and content/type where practical.
- Enforce file-size limits.
- Use safe temporary storage and generated internal filenames.
- Apply restrictive permissions.
- Clean up temporary files.
- Use processing/resource limits and timeouts.

## Never Execute Captured Content
Never execute files, scripts or payloads found in traffic. Never automatically open URLs.

## Parser Isolation
Treat parser libraries as attack surface. Catch failures, limit resources and prevent one malformed packet from crashing the application. A future hosted deployment should consider isolated worker/container processing.

## Resource Exhaustion
Protect against huge captures, pathological protocol structures, excessive flows, DNS events and timeline events. Use configurable limits and graceful degradation.

## Path Traversal
Never construct filesystem paths directly from user-controlled filenames.

## Web UI Safety
Escape untrusted values from domains, URLs, headers, user agents, hostnames and payload-derived text. Prevent XSS/HTML injection.

## URL Handling
Do not automatically fetch discovered URLs. Future enrichment must explicitly defend against SSRF, redirects, localhost/private ranges, internal DNS and cloud metadata endpoints.

## Secrets
No hard-coded API keys, tokens or passwords. Use environment variables or secret management. Never commit real `.env` secrets.

## AI Security
Captured text can contain prompt injection. Treat extracted content strictly as data. Do not send raw packet contents to an external AI provider unless a future feature explicitly requires it and privacy/security controls are established. Prefer structured evidence summaries.

## Privacy
PCAPs may contain sensitive data. Minimize persistence, provide cleanup, disclose external AI processing and avoid unnecessary payload logging.

## Logging
Do not unnecessarily log full payloads, credentials or tokens. Logs should support debugging without becoming a duplicate PCAP.

## Hosted Deployment
A public multi-user deployment requires authentication, authorization, investigation isolation and secure sessions. Local prototype assumptions are not sufficient for public deployment.

## Dependency Security
Control dependency versions, review dependencies and use vulnerability scanning where practical.

## Security Testing
Test malformed/oversized captures, malicious strings, XSS, path traversal, parser failures, resource exhaustion and unauthorized access.

**Principle:** TRACE must never become more dangerous than the evidence it analyzes. Passive analysis is the default.
