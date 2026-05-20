"""Gateway configuration, env-driven via pydantic-settings.

All variables are GW_-prefixed in the environment, e.g.
  GW_OLLAMA_BASE_URL=http://ollama.internal:11434
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GW_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    # Server
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "info"

    # Upstream provider (one for now; selection/routing comes with the policy engine)
    provider: str = "ollama"
    ollama_base_url: str = "http://localhost:11434"

    # Default model used if a client request omits the field.
    default_model: str = "qwen3:14b"


settings = Settings()
