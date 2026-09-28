import uuid
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, IPv6
from scapy.layers import inet6
from scapy.utils import PcapNgReader, PcapReader

from app.schemas.flow import Flow


def aggregate_flows(path: Path, file_format: str, investigation_id: str) -> list[Flow]:
    """Aggregate bidirectional network flows from a PCAP/PCAPNG capture file.

    Groups packets into flows keyed by canonical endpoint pairs and protocol.
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

    flow_stats: dict[tuple[str, int, str, int, str], dict] = defaultdict(
        lambda: {
            "first_seen": None,
            "last_seen": None,
            "packets_sent": 0,
            "packets_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "saw_syn": False,
            "saw_syn_ack": False,
            "fin_src": False,
            "fin_dst": False,
            "saw_rst": False,
        }
    )

    try:
        with reader_cls(str(path)) as reader:
            for pkt in reader:
                pkt_time = float(pkt.time)
                pkt_len = len(pkt)

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

                protocol: str | None = None
                src_port = 0
                dst_port = 0

                if pkt.haslayer(TCP):
                    protocol = "TCP"
                    src_port = int(pkt[TCP].sport)
                    dst_port = int(pkt[TCP].dport)
                elif pkt.haslayer(UDP):
                    protocol = "UDP"
                    src_port = int(pkt[UDP].sport)
                    dst_port = int(pkt[UDP].dport)
                elif pkt.haslayer(ICMP):
                    protocol = "ICMP"
                    src_port = 0
                    dst_port = 0
                elif any(
                    issubclass(layer, inet6._ICMPv6) or layer.__name__.startswith("ICMPv6")
                    for layer in pkt.layers()
                ):
                    protocol = "ICMPv6"
                    src_port = 0
                    dst_port = 0

                if protocol is None:
                    continue

                # Canonicalize endpoints
                # Sort deterministically: IP string first, then port
                if (src_ip, src_port) <= (dst_ip, dst_port):
                    canonical_src_ip, canonical_src_port = src_ip, src_port
                    canonical_dst_ip, canonical_dst_port = dst_ip, dst_port
                    is_sent = True
                else:
                    canonical_src_ip, canonical_src_port = dst_ip, dst_port
                    canonical_dst_ip, canonical_dst_port = src_ip, src_port
                    is_sent = False

                flow_key = (
                    canonical_src_ip,
                    canonical_src_port,
                    canonical_dst_ip,
                    canonical_dst_port,
                    protocol,
                )
                stat = flow_stats[flow_key]

                if stat["first_seen"] is None or pkt_time < stat["first_seen"]:
                    stat["first_seen"] = pkt_time
                if stat["last_seen"] is None or pkt_time > stat["last_seen"]:
                    stat["last_seen"] = pkt_time

                if is_sent:
                    stat["packets_sent"] += 1
                    stat["bytes_sent"] += pkt_len
                else:
                    stat["packets_received"] += 1
                    stat["bytes_received"] += pkt_len

                if protocol == "TCP":
                    flags = int(pkt[TCP].flags)
                    is_fin = bool(flags & 0x01)
                    is_syn = bool(flags & 0x02)
                    is_rst = bool(flags & 0x04)
                    is_ack = bool(flags & 0x10)

                    if is_rst:
                        stat["saw_rst"] = True
                    if is_syn and is_ack:
                        stat["saw_syn_ack"] = True
                    elif is_syn:
                        stat["saw_syn"] = True

                    if is_fin:
                        if is_sent:
                            stat["fin_src"] = True
                        else:
                            stat["fin_dst"] = True

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(
            f"Failed to aggregate flows from capture file '{path.name}': {exc}"
        ) from exc

    if not flow_stats:
        return []

    flows: list[Flow] = []
    for flow_key in sorted(flow_stats.keys()):
        src_ip, src_port, dst_ip, dst_port, protocol = flow_key
        stat = flow_stats[flow_key]

        if protocol == "TCP":
            # Precedence: reset > closed > established > syn_sent > unknown
            if stat["saw_rst"]:
                tcp_state = "reset"
            elif stat["fin_src"] and stat["fin_dst"]:
                tcp_state = "closed"
            elif stat["saw_syn_ack"]:
                tcp_state = "established"
            elif stat["saw_syn"]:
                tcp_state = "syn_sent"
            else:
                tcp_state = "unknown"
        else:
            tcp_state = None

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

        flows.append(
            Flow(
                id=uuid.uuid4().hex,
                investigation_id=investigation_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                packets_sent=stat["packets_sent"],
                packets_received=stat["packets_received"],
                bytes_sent=stat["bytes_sent"],
                bytes_received=stat["bytes_received"],
                first_seen=first_seen_iso,
                last_seen=last_seen_iso,
                tcp_state=tcp_state,
            )
        )

    return flows
