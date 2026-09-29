from pydantic import BaseModel, ConfigDict


class DnsRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    query: str
    query_type: str
    response_code: int
    answers: list[str]
