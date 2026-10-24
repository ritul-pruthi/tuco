from pydantic import BaseModel


class AiReportRecord(BaseModel):
    id: str
    investigation_id: str
    model: str
    prompt_version: str
    report: dict
    markdown: str
    warnings: list[dict]
    created_at: str


class AiSummaryResponse(BaseModel):
    report_id: str
    report: dict
    markdown: str
    provider: str
    model: str
    prompt_version: str
    generated_at: str
    warnings: list[dict] = []
