import uuid
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from scapy.all import ARP, IP, TCP, UDP, IPv6
from scapy.utils import PcapNgReader, PcapReader

from app.core.scope import classify_scope
from app.schemas.host import Host


def aggregate_hosts(path: Path, file_format: str, investigation_id: str) -> list[Host]:
    """Aggregate host records from a PCAP/PCAPNG capture file.

    Streams packets and computes traffic statistics, scope, and first observed MAC for
    every unique IP address.
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

    mac_by_ip: dict[str, str] = {}
    host_stats: dict[str, dict] = defaultdict(
        lambda: {
            "first_seen": None,
            "last_seen": None,
            "packets_sent": 0,
            "packets_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "destinations": set(),
            "ports": set(),
        }
    )

    try:
        with reader_cls(str(path)) as reader:
            for pkt in reader:
                pkt_time = float(pkt.time)
                pkt_len = len(pkt)

                # MAC tracking from ARP
                if pkt.haslayer(ARP):
                    arp_layer = pkt[ARP]
                    if arp_layer.op == 2 and arp_layer.psrc and arp_layer.hwsrc:
                        psrc = str(arp_layer.psrc)
                        hwsrc = str(arp_layer.hwsrc)
                        if hwsrc and psrc not in mac_by_ip:
                            mac_by_ip[psrc] = hwsrc
                    elif arp_layer.op == 1 and arp_layer.pdst and arp_layer.hwdst:
                        pdst = str(arp_layer.pdst)
                        hwdst = str(arp_layer.hwdst)
                        if hwdst and hwdst != "00:00:00:00:00:00" and pdst not in mac_by_ip:
                            mac_by_ip[pdst] = hwdst

                # Extract IP endpoints
                src_ip: str | None = None
                dst_ip: str | None = None

                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    if ip_layer.src:
                        src_ip = str(ip_layer.src)
                    if ip_layer.dst:
                        dst_ip = str(ip_layer.dst)
                elif pkt.haslayer(IPv6):
                    ipv6_layer = pkt[IPv6]
                    if ipv6_layer.src:
                        src_ip = str(ipv6_layer.src)
                    if ipv6_layer.dst:
                        dst_ip = str(ipv6_layer.dst)

                if src_ip is None or dst_ip is None:
                    continue

                # Destination port tracking
                dst_port: int | None = None
                if pkt.haslayer(TCP):
                    dst_port = int(pkt[TCP].dport)
                elif pkt.haslayer(UDP):
                    dst_port = int(pkt[UDP].dport)

                # Update source host stats
                src_stat = host_stats[src_ip]
                src_stat["packets_sent"] += 1
                src_stat["bytes_sent"] += pkt_len
                src_stat["destinations"].add(dst_ip)
                if dst_port is not None:
                    src_stat["ports"].add(dst_port)

                if src_stat["first_seen"] is None or pkt_time < src_stat["first_seen"]:
                    src_stat["first_seen"] = pkt_time
                if src_stat["last_seen"] is None or pkt_time > src_stat["last_seen"]:
                    src_stat["last_seen"] = pkt_time

                # Update destination host stats
                dst_stat = host_stats[dst_ip]
                dst_stat["packets_received"] += 1
                dst_stat["bytes_received"] += pkt_len

                if dst_stat["first_seen"] is None or pkt_time < dst_stat["first_seen"]:
                    dst_stat["first_seen"] = pkt_time
                if dst_stat["last_seen"] is None or pkt_time > dst_stat["last_seen"]:
                    dst_stat["last_seen"] = pkt_time

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to aggregate hosts from capture file '{path.name}': {exc}") from exc

    if not host_stats:
        return []

    hosts: list[Host] = []
    for ip in sorted(host_stats.keys()):
        stat = host_stats[ip]
        first_seen_iso = (
            datetime.fromtimestamp(stat["first_seen"], tz=UTC).isoformat()
            if stat["first_seen"] is not None
            else datetime.now(UTC).isoformat()
        )
        last_seen_iso = (
            datetime.fromtimestamp(stat["last_seen"], tz=UTC).isoformat()
            if stat["last_seen"] is not None
            else datetime.now(UTC).isoformat()
        )

        hosts.append(
            Host(
                id=uuid.uuid4().hex,
                investigation_id=investigation_id,
                ip=ip,
                mac=mac_by_ip.get(ip),
                scope=classify_scope(ip),
                packets_sent=stat["packets_sent"],
                packets_received=stat["packets_received"],
                bytes_sent=stat["bytes_sent"],
                bytes_received=stat["bytes_received"],
                unique_destinations=len(stat["destinations"]),
                unique_ports=len(stat["ports"]),
                first_seen=first_seen_iso,
                last_seen=last_seen_iso,
            )
        )

    return hosts
