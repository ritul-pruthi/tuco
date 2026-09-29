from pydantic import BaseModel, ConfigDict


class HttpRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    method: str
    host: str | None
    path: str | None
    user_agent: str | None
    status_code: int | None
