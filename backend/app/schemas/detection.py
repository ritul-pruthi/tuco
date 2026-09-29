from pydantic import BaseModel, ConfigDict, Field


class Detection(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    rule_id: str
    title: str
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    confidence: str = Field(pattern="^(low|medium|high)$")
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    timeframe_start: str
    timeframe_end: str
    observed_metric: str
    observed_value: float
    threshold_description: str
    threshold_value: float
    explanation: str
    evidence: list[dict]
    limitations: str
    created_at: str
