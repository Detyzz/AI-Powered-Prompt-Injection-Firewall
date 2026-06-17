from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env."""

    app_name: str = "AI Prompt Injection Firewall"
    llm_provider: Literal["none", "gemini", "openai"] = "none"
    block_threshold: int = Field(default=70, ge=0, le=100)
    warn_threshold: int = Field(default=40, ge=0, le=100)

    gemini_api_key: str | None = None
    gemini_model: str = "gemini-1.5-flash"

    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"

    request_timeout_seconds: float = 15.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
