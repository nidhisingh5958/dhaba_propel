"""
Application Configuration.
"""

from typing import Optional
import os
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration settings loaded from environment or .env file.
    """
    GEMINI_API_KEY: Optional[str] = Field(default=None, description="API Key for Google Gemini")
    OPENAI_API_KEY: Optional[str] = Field(default=None, description="API Key for OpenAI")

    # TRIAGE_MODE is "replay" by default if no API key is configured.
    # Can be explicitly set to "live" or "replay".
    TRIAGE_MODE: str = Field(
        default="replay",
        description="Operating mode: 'replay' (deterministic fixtures) or 'live' (LLM calls)"
    )

    DB_PATH: str = Field(
        default="triage_state.db",
        description="Path to SQLite database for ticket deduplication and state"
    )

    CONFIDENCE_THRESHOLD: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Threshold below which triage must escalate to human (needs_human=True)"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @model_validator(mode="after")
    def resolve_mode_and_defaults(self) -> "Settings":
        # If no API key is set, fallback to replay mode
        has_key = bool(self.GEMINI_API_KEY or self.OPENAI_API_KEY)
        if not has_key:
            self.TRIAGE_MODE = "replay"
        elif "TRIAGE_MODE" not in os.environ and self.TRIAGE_MODE == "replay":
            # If an API key is provided and TRIAGE_MODE wasn't explicitly forced to replay in env
            self.TRIAGE_MODE = "live"
        return self


settings = Settings()

