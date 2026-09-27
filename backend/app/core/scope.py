import ipaddress

INTERNAL_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("::1/128"),
]


def classify_scope(ip: str) -> str:
    """Classify an IP address as 'internal', 'external', or 'unknown'."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return "unknown"

    for net in INTERNAL_NETWORKS:
        if addr.version == net.version and addr in net:
            return "internal"

    return "external"
