from pydantic import BaseModel, Field


class PcapSummary(BaseModel):
    packet_count: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    duration_seconds: float | None = None
    protocols: list[str] = Field(default_factory=list)
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
