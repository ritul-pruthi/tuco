# Twenty ports is high enough to indicate probing while avoiding ordinary connections.
PORT_SCAN_MIN_DISTINCT_PORTS = 20
# Ten seconds captures a concentrated scan without treating slow activity as one burst.
PORT_SCAN_WINDOW_SECONDS = 10
# Port scans are noteworthy, but the behavior alone is not evidence of compromise.
PORT_SCAN_SEVERITY = "medium"
# The threshold is deterministic, but legitimate tools can produce the same pattern.
PORT_SCAN_CONFIDENCE = "medium"

# Five internal targets in a short burst is enough to indicate probing while allowing small service checks.
INTERNAL_RECON_MIN_DISTINCT_TARGETS = 5
# Thirty seconds captures concentrated discovery activity without grouping routine periodic checks.
INTERNAL_RECON_WINDOW_SECONDS = 30
# Internal target discovery is noteworthy, but the behavior alone is not evidence of compromise.
INTERNAL_RECON_SEVERITY = "medium"
# The threshold is deterministic, but legitimate inventory and vulnerability tools can produce the same pattern.
INTERNAL_RECON_CONFIDENCE = "medium"

# Ten observations provide enough samples to distinguish a repeated pattern from a single connection burst.
BEACON_MIN_OBSERVATIONS = 10
# A minute-long span gives periodic behavior enough time to become meaningful.
BEACON_MIN_DURATION_SECONDS = 60
# A CV below 0.20 represents sufficiently regular intervals for a deterministic beacon heuristic.
BEACON_MAX_INTERVAL_CV = 0.20
# Sub-second intervals are more likely to reflect packet noise than application check-ins.
BEACON_MIN_INTERVAL_SECONDS = 1
# Periodic communication is noteworthy, but the pattern alone is not evidence of compromise.
BEACON_SEVERITY = "medium"
# Periodic traffic has many legitimate causes, so confidence remains low without payload context.
BEACON_CONFIDENCE = "low"

# Queries longer than 52 characters are uncommon in ordinary DNS lookups.
DNS_LONG_QUERY_LENGTH = 52
# One hundred queries in a minute indicates unusually concentrated DNS activity.
DNS_HIGH_FREQUENCY_COUNT = 100
# This window captures short DNS bursts without grouping routine activity across minutes.
DNS_HIGH_FREQUENCY_WINDOW_SECONDS = 60
# Twenty distinct subdomains under one parent indicates unusual name variability.
DNS_SUBDOMAIN_VARIABILITY_THRESHOLD = 20
# Ten failed responses indicate a repeated DNS resolution problem worth investigating.
DNS_REPEATED_FAILURE_COUNT = 10
# DNS anomaly indicators are low-severity observations requiring investigation.
DNS_ANOMALY_SEVERITY = "low"
# DNS anomaly indicators have low confidence because legitimate software can produce them.
DNS_ANOMALY_CONFIDENCE = "low"

# Common scanner/tool user agents, case-insensitive match.
HTTP_SUSPICIOUS_UA_SUBSTRINGS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "curl/",
    "python-requests",
    "wget",
    "zgrab",
    "gobuster",
    "dirbuster",
    "hydra",
    "metasploit",
]
# Twenty HTTP errors in one minute indicates an unusually concentrated error burst.
HTTP_HIGH_ERROR_RATE_COUNT = 20
HTTP_HIGH_ERROR_RATE_WINDOW_SECONDS = 60
# Case-insensitive substring match for paths commonly probed by scanners or attackers.
HTTP_SUSPICIOUS_PATH_SUBSTRINGS = [
    "/../",
    "/etc/passwd",
    "/.env",
    "/wp-admin",
    "/phpmyadmin",
    "/.git",
    "/admin",
    "/shell",
    "/cmd",
    "/cgi-bin",
]
# HTTP indicators are low-severity observations requiring investigation.
HTTP_INDICATOR_SEVERITY = "low"
# Legitimate tools can produce these patterns, so confidence remains low.
HTTP_INDICATOR_CONFIDENCE = "low"
