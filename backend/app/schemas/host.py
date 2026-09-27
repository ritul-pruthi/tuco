from pydantic import BaseModel, ConfigDict


class Host(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    ip: str
    mac: str | None = None
    scope: str
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int
    unique_destinations: int
    unique_ports: int
    first_seen: str
    last_seen: str
