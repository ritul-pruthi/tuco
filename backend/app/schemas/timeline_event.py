from pydantic import BaseModel, ConfigDict


class TimelineEvent(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    timestamp: str
    event_type: str
    source: str
    destination: str
    summary: str
    evidence_type: str
    evidence_id: str
