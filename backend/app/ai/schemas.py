from pydantic import BaseModel


class AiSummaryResponse(BaseModel):
    raw_output: str
    provider: str
    model: str
    prompt_version: str
    generated_at: str
    warnings: list[dict] = []
