from pydantic import BaseModel, ConfigDict


class Ioc(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    ioc_type: str
    value: str
    first_seen: str
    last_seen: str
    occurrences: int
    scope: str
    evidence_type: str
    evidence_ids: list[str]
