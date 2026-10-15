from pydantic import BaseModel


class AiSummaryResponse(BaseModel):
    report: dict
    markdown: str
    provider: str
    model: str
    prompt_version: str
    generated_at: str
    warnings: list[dict] = []
