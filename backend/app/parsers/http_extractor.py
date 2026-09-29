import uuid
from datetime import UTC, datetime
from pathlib import Path

from scapy.all import IP, TCP, IPv6
from scapy.layers.http import HTTPRequest, HTTPResponse

from app.parsers.pcap_parser import get_reader_class
from app.schemas.http_record import HttpRecord


def _header_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _packet_endpoints(packet) -> tuple[str, int, str, int] | None:
    if not packet.haslayer(TCP):
        return None
    if packet.haslayer(IP):
        ip_layer = packet[IP]
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
    else:
        return None
    tcp_layer = packet[TCP]
    return str(ip_layer.src), int(tcp_layer.sport), str(ip_layer.dst), int(tcp_layer.dport)


def extract_http(path: Path, file_format: str, investigation_id: str) -> list[HttpRecord]:
    if not path.is_file():
        raise ValueError(f"Capture file does not exist: '{path}'")

    records_by_flow: dict[tuple[str, int, str, int], HttpRecord] = {}
    reader_cls = get_reader_class(file_format)
    try:
        with reader_cls(str(path)) as reader:
            for packet in reader:
                endpoints = _packet_endpoints(packet)
                if endpoints is None:
                    continue
                source_ip, source_port, destination_ip, destination_port = endpoints

                if packet.haslayer(HTTPRequest):
                    if source_port == 443 or destination_port == 443:
                        continue
                    request = packet[HTTPRequest]
                    flow_key = endpoints
                    records_by_flow[flow_key] = HttpRecord(
                        id=uuid.uuid4().hex,
                        investigation_id=investigation_id,
                        timestamp=datetime.fromtimestamp(float(packet.time), tz=UTC).isoformat(),
                        source_ip=source_ip,
                        source_port=source_port,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        method=_header_text(request.Method) or "",
                        host=_header_text(request.Host),
                        path=_header_text(request.Path),
                        user_agent=_header_text(request.User_Agent),
                        status_code=None,
                    )

                if packet.haslayer(HTTPResponse):
                    response_key = (destination_ip, destination_port, source_ip, source_port)
                    record = records_by_flow.get(response_key)
                    if record is not None and record.status_code is None:
                        record.status_code = int(packet[HTTPResponse].Status_Code)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to extract HTTP from capture file '{path.name}': {exc}") from exc

    return sorted(records_by_flow.values(), key=lambda record: record.timestamp)
