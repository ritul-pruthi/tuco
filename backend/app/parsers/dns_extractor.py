import uuid
from datetime import UTC, datetime
from pathlib import Path

from scapy.all import DNS, IP, IPv6

from app.parsers.pcap_parser import get_reader_class
from app.schemas.dns_record import DnsRecord

_DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}


def _as_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b".").decode("utf-8", errors="replace")
    return str(value).rstrip(".")


def _answer_values(dns_layer) -> list[str]:
    answers: list[str] = []
    for index in range(int(dns_layer.ancount or 0)):
        answer = dns_layer.an[index]
        answers.append(_as_text(answer.rdata))
    return answers


def extract_dns(path: Path, file_format: str, investigation_id: str) -> list[DnsRecord]:
    if not path.is_file():
        raise ValueError(f"Capture file does not exist: '{path}'")

    records: list[DnsRecord] = []
    reader_cls = get_reader_class(file_format)
    try:
        with reader_cls(str(path)) as reader:
            for packet in reader:
                if not packet.haslayer(DNS):
                    continue
                dns_layer = packet[DNS]
                if dns_layer.qr != 1 or not dns_layer.qd:
                    continue

                if packet.haslayer(IP):
                    source_ip = str(packet[IP].src)
                    destination_ip = str(packet[IP].dst)
                elif packet.haslayer(IPv6):
                    source_ip = str(packet[IPv6].src)
                    destination_ip = str(packet[IPv6].dst)
                else:
                    continue

                query_type = int(dns_layer.qd.qtype)
                records.append(
                    DnsRecord(
                        id=uuid.uuid4().hex,
                        investigation_id=investigation_id,
                        timestamp=datetime.fromtimestamp(float(packet.time), tz=UTC).isoformat(),
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        query=_as_text(dns_layer.qd.qname),
                        query_type=_DNS_TYPES.get(query_type, f"TYPE{query_type}"),
                        response_code=int(dns_layer.rcode),
                        answers=_answer_values(dns_layer),
                    )
                )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to extract DNS from capture file '{path.name}': {exc}") from exc

    return records
