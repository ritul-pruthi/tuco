import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scapy.all import IP, TCP, IPv6, load_layer

try:
    from scapy.layers.tls.all import TLS
    from scapy.layers.tls.handshake import TLSCertificate, TLSClientHello, TLSServerHello
except ImportError:
    load_layer("tls")
    from scapy.layers.tls.all import TLS
    from scapy.layers.tls.handshake import TLSCertificate, TLSClientHello, TLSServerHello

from app.parsers.pcap_parser import get_reader_class
from app.schemas.tls_record import TlsRecord

logger = logging.getLogger(__name__)

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def _version_name(version: object) -> str | None:
    if isinstance(version, int):
        return TLS_VERSIONS.get(version)
    if isinstance(version, str):
        for name in TLS_VERSIONS.values():
            if name in version:
                return name
    return None


def _extension_type(extension: object) -> int | None:
    extension_type = getattr(extension, "type", None)
    if isinstance(extension_type, int):
        return extension_type
    type_name = str(extension_type).lower()
    if "server name" in type_name or "servername" in type_name:
        return 0x0000
    if "supported version" in type_name or "supported_versions" in type_name:
        return 0x002B
    return None


def _client_hello_metadata(hello: TLSClientHello) -> tuple[str | None, str | None]:
    sni = None
    tls_version = _version_name(getattr(hello, "version", None))
    for extension in getattr(hello, "ext", []) or []:
        extension_type = _extension_type(extension)
        if extension_type == 0x0000 and sni is None:
            server_names = getattr(extension, "servernames", None) or []
            if server_names:
                value = server_names[0]
                value = getattr(value, "servername", value)
                sni = value.decode(errors="replace") if isinstance(value, bytes) else str(value)
        elif extension_type == 0x002B:
            versions = getattr(extension, "versions", None) or []
            for version in reversed(versions):
                tls_version = _version_name(version) or tls_version
                if tls_version == "TLS 1.3":
                    break
    return sni, tls_version


def _certificate_metadata(certificate: TLSCertificate) -> tuple[str, str, str, str] | None:
    from cryptography import x509

    metadata = None
    for certificate_entry in getattr(certificate, "certs", []) or []:
        try:
            parsed = x509.load_der_x509_certificate(certificate_entry.data)
            not_before = getattr(parsed, "not_valid_before_utc", parsed.not_valid_before)
            not_after = getattr(parsed, "not_valid_after_utc", parsed.not_valid_after)
            metadata = (
                parsed.subject.rfc4514_string(),
                parsed.issuer.rfc4514_string(),
                not_before.isoformat(),
                not_after.isoformat(),
            )
            break
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping unparseable TLS certificate: %s", exc)
    return metadata


def _packet_tls(packet: object) -> TLS:
    if packet.haslayer(TLS):
        return packet[TLS]
    return TLS(bytes(packet[TCP].payload))


def extract_tls(path: Path, file_format: str, investigation_id: str) -> list[TlsRecord]:
    if not path.is_file():
        raise ValueError(f"Capture file does not exist: '{path}'")

    reader_cls = get_reader_class(file_format)
    records: dict[tuple[str, int, str, int], TlsRecord] = {}

    try:
        with reader_cls(str(path)) as reader:
            for packet in reader:
                if not packet.haslayer(TCP):
                    continue
                tcp = packet[TCP]
                if tcp.dport != 443 and tcp.sport != 443:
                    continue

                ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                if ip_layer is None:
                    continue
                stream_key = (str(ip_layer.src), int(tcp.sport), str(ip_layer.dst), int(tcp.dport))
                reverse_key = (stream_key[2], stream_key[3], stream_key[0], stream_key[1])

                tls = None
                try:
                    tls = _packet_tls(packet)
                    client_hello = tls.getlayer(TLSClientHello)
                    server_hello = tls.getlayer(TLSServerHello)
                    certificate = tls.getlayer(TLSCertificate)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Skipping unparseable TLS packet: %s", exc)
                if tls is None:
                    continue

                if client_hello is not None and stream_key not in records:
                    sni, tls_version = _client_hello_metadata(client_hello)
                    timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC).isoformat()
                    records[stream_key] = TlsRecord(
                        id=uuid.uuid4().hex,
                        investigation_id=investigation_id,
                        timestamp=timestamp,
                        source_ip=stream_key[0],
                        source_port=stream_key[1],
                        destination_ip=stream_key[2],
                        destination_port=stream_key[3],
                        sni=sni,
                        tls_version=tls_version,
                        certificate_subject=None,
                        certificate_issuer=None,
                        certificate_not_before=None,
                        certificate_not_after=None,
                    )

                record = records.get(reverse_key)
                if record is None:
                    continue
                if server_hello is not None:
                    server_version = _version_name(getattr(server_hello, "version", None))
                    if server_version == "TLS 1.3":
                        record.tls_version = server_version
                if certificate is not None:
                    metadata = _certificate_metadata(certificate)
                    if metadata is not None:
                        (
                            record.certificate_subject,
                            record.certificate_issuer,
                            record.certificate_not_before,
                            record.certificate_not_after,
                        ) = metadata
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to extract TLS from capture file '{path.name}': {exc}") from exc

    return sorted(records.values(), key=lambda record: (record.timestamp, record.id))
