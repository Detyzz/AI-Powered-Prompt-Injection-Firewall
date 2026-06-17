from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import Settings, get_settings
from app.detectors import local_threat_analysis, sanitize_prompt
from app.llm_clients import analyze_with_llm
from app.schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse

app = FastAPI(
    title="AI Prompt Injection Firewall",
    description="A FastAPI shield that scores prompts before they reach an AI application.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["health"])
async def root() -> dict[str, str]:
    return {
        "message": "AI Prompt Injection Firewall is running.",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(
        status="ok",
        provider=settings.llm_provider,
        block_threshold=settings.block_threshold,
        warn_threshold=settings.warn_threshold,
    )


@app.post("/analyze", response_model=AnalyzeResponse, tags=["firewall"])
async def analyze_prompt(
    request: AnalyzeRequest,
    settings: Settings = Depends(get_settings),
) -> AnalyzeResponse:
    heuristic = local_threat_analysis(request.prompt)
    provider = "heuristic"
    merged = heuristic

    try:
        llm_result = await analyze_with_llm(request.prompt, settings)
    except Exception:
        llm_result = None

    if llm_result:
        provider = settings.llm_provider
        merged = _merge_analysis(heuristic, llm_result)

    threat_score = _coerce_score(merged.get("threat_score", heuristic["threat_score"]))
    decision = _decision_from_score(threat_score, settings)
    reasons = _coerce_string_list(merged.get("reasons")) or heuristic["reasons"]
    category = str(merged.get("category") or heuristic["category"])
    confidence = _coerce_confidence(merged.get("confidence", heuristic["confidence"]))

    return AnalyzeResponse(
        threat_score=threat_score,
        decision=decision,
        category=category,
        confidence=confidence,
        reasons=reasons,
        signals=heuristic["signals"],
        sanitized_prompt=sanitize_prompt(request.prompt),
        provider=provider,  # type: ignore[arg-type]
    )


def _merge_analysis(heuristic: dict, llm_result: dict) -> dict:
    llm_score = _coerce_score(llm_result.get("threat_score", 0))
    heuristic_score = _coerce_score(heuristic.get("threat_score", 0))
    final_score = max(heuristic_score, round((llm_score * 0.7) + (heuristic_score * 0.3)))

    return {
        "threat_score": final_score,
        "category": llm_result.get("category") or heuristic.get("category"),
        "confidence": llm_result.get("confidence") or heuristic.get("confidence"),
        "reasons": _coerce_string_list(llm_result.get("reasons")) or heuristic.get("reasons"),
    }


def _decision_from_score(score: int, settings: Settings) -> str:
    if score >= settings.block_threshold:
        return "block"
    if score >= settings.warn_threshold:
        return "warn"
    return "allow"


def _coerce_score(value: object) -> int:
    try:
        return max(0, min(100, int(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _coerce_confidence(value: object) -> float:
    try:
        return max(0.0, min(1.0, round(float(value), 2)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.5


def _coerce_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]
