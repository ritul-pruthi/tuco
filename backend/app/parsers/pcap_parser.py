from pathlib import Path

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6
from scapy.layers import inet6
from scapy.utils import PcapNgReader, PcapReader

from app.schemas.pcap_summary import PcapSummary


def parse_pcap(path: Path, file_format: str) -> PcapSummary:
    """Parse a PCAP or PCAPNG capture file and return a summary of basic facts.

    Uses streaming readers to process packets one-by-one without loading the entire
    capture into memory.
    """
    normalized_format = file_format.lower().lstrip(".")
    if normalized_format == "pcapng":
        reader_cls = PcapNgReader
    elif normalized_format == "pcap":
        reader_cls = PcapReader
    else:
        raise ValueError(f"Unsupported capture file format: '{file_format}'")

    if not path.is_file():
        raise ValueError(f"Capture file does not exist: '{path}'")

    packet_count = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    protocols: set[str] = set()
    ipv4_addresses: set[str] = set()
    ipv6_addresses: set[str] = set()

    try:
        with reader_cls(str(path)) as reader:
            for pkt in reader:
                packet_count += 1
                pkt_time = float(pkt.time)

                if first_timestamp is None or pkt_time < first_timestamp:
                    first_timestamp = pkt_time
                if last_timestamp is None or pkt_time > last_timestamp:
                    last_timestamp = pkt_time

                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    if ip_layer.src:
                        ipv4_addresses.add(str(ip_layer.src))
                    if ip_layer.dst:
                        ipv4_addresses.add(str(ip_layer.dst))

                if pkt.haslayer(IPv6):
                    ipv6_layer = pkt[IPv6]
                    if ipv6_layer.src:
                        ipv6_addresses.add(str(ipv6_layer.src))
                    if ipv6_layer.dst:
                        ipv6_addresses.add(str(ipv6_layer.dst))

                if pkt.haslayer(TCP):
                    protocols.add("TCP")
                if pkt.haslayer(UDP):
                    protocols.add("UDP")
                if pkt.haslayer(ICMP):
                    protocols.add("ICMP")
                if pkt.haslayer(ARP):
                    protocols.add("ARP")
                if pkt.haslayer(DNS):
                    protocols.add("DNS")
                if any(
                    issubclass(layer, inet6._ICMPv6) or layer.__name__.startswith("ICMPv6")
                    for layer in pkt.layers()
                ):
                    protocols.add("ICMPv6")

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to parse capture file '{path.name}': {exc}") from exc

    if packet_count == 0:
        return PcapSummary(
            packet_count=0,
            first_timestamp=None,
            last_timestamp=None,
            duration_seconds=None,
            protocols=[],
            ipv4_addresses=[],
            ipv6_addresses=[],
        )

    duration_seconds = (
        max(0.0, float(last_timestamp - first_timestamp))
        if first_timestamp is not None and last_timestamp is not None
        else None
    )

    return PcapSummary(
        packet_count=packet_count,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
        duration_seconds=duration_seconds,
        protocols=sorted(protocols),
        ipv4_addresses=sorted(ipv4_addresses),
        ipv6_addresses=sorted(ipv6_addresses),
    )
