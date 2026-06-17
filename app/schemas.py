from typing import Literal

from pydantic import BaseModel, Field


Decision = Literal["allow", "warn", "block"]


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=12000)
    user_id: str | None = Field(default=None, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)


class ThreatSignal(BaseModel):
    name: str
    description: str
    severity: Literal["low", "medium", "high"]


class AnalyzeResponse(BaseModel):
    threat_score: int = Field(..., ge=0, le=100)
    decision: Decision
    category: str
    confidence: float = Field(..., ge=0, le=1)
    reasons: list[str]
    signals: list[ThreatSignal]
    sanitized_prompt: str
    provider: Literal["heuristic", "gemini", "openai"]


class HealthResponse(BaseModel):
    status: str
    provider: str
    block_threshold: int
    warn_threshold: int
