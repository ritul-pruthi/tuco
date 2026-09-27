from pydantic import BaseModel, ConfigDict


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    format: str
    size_bytes: int
    packet_count: int | None = None
    started_at: str | None = None
    ended_at: str | None = None
    duration_seconds: float | None = None
    status: str
    created_at: str
