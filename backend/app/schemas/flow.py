from pydantic import BaseModel, ConfigDict


class Flow(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int
    first_seen: str
    last_seen: str
    tcp_state: str | None = None
