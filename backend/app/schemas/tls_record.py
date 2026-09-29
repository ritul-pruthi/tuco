from pydantic import BaseModel, ConfigDict


class TlsRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    sni: str | None
    tls_version: str | None
    certificate_subject: str | None
    certificate_issuer: str | None
    certificate_not_before: str | None
    certificate_not_after: str | None
