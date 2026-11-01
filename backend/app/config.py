"""Application configuration for Vulnex AI."""

import json
import os
from typing import List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Vulnex AI Backend"
    app_version: str = "1.0.0"
    vulnex_env: str = Field(default="development", alias="VULNEX_ENV")
    vulnex_host: str = Field(default="0.0.0.0", alias="VULNEX_HOST")
    vulnex_port: int = Field(default=8000, alias="VULNEX_PORT")
    
    cors_origins: Union[List[str], str] = Field(
        default=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "*"
        ],
        alias="CORS_ORIGINS"
    )
    frontend_origin: Optional[str] = Field(default=None, alias="FRONTEND_ORIGIN")

    # AI Provider Configuration
    ai_provider: str = Field(default="gemini", alias="AI_PROVIDER")
    ai_model: Optional[str] = Field(default=None, alias="AI_MODEL")
    ai_api_key: Optional[str] = Field(default=None, alias="AI_API_KEY")
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-1.5-pro", alias="GEMINI_MODEL")

    # AI Reliability Limits
    ai_timeout_seconds: int = Field(default=15, alias="AI_TIMEOUT_SECONDS")
    ai_max_retries: int = Field(default=2, alias="AI_MAX_RETRIES")

    max_scan_file_size_bytes: int = Field(default=2 * 1024 * 1024, alias="MAX_SCAN_FILE_SIZE_BYTES")  # 2MB
    max_repo_clone_size_bytes: int = Field(default=20 * 1024 * 1024, alias="MAX_REPO_CLONE_SIZE_BYTES")  # 20MB
    repo_clone_timeout_seconds: int = Field(default=30, alias="REPO_CLONE_TIMEOUT_SECONDS")

    database_path: str = Field(default="vulnex.db", alias="DATABASE_PATH")
    artifacts_dir: str = Field(default="artifacts", alias="ARTIFACTS_DIR")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                try:
                    return json.loads(value)
                except Exception:
                    pass
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    def get_effective_cors_origins(self) -> List[str]:
        origins = list(self.cors_origins) if isinstance(self.cors_origins, list) else [str(self.cors_origins)]
        if self.frontend_origin:
            for item in self.frontend_origin.split(","):
                clean = item.strip()
                if clean and clean not in origins:
                    origins.append(clean)
        return origins

    def get_effective_ai_api_key(self) -> str:
        key = self.ai_api_key or self.gemini_api_key or ""
        return key.strip()

    def get_effective_ai_model(self) -> str:
        model = self.ai_model or self.gemini_model or "gemini-1.5-pro"
        return model.strip()

    def is_ai_configured(self) -> bool:
        return bool(self.get_effective_ai_api_key())


settings = Settings()
