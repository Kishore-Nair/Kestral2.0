"""Application configuration loaded from the repository-root .env file."""

from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PositiveInt = Annotated[int, Field(gt=0)]


def _resolve_project_path(value: Path) -> Path:
    candidate = value if value.is_absolute() else PROJECT_ROOT / value
    resolved = candidate.resolve()
    try:
        resolved.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError("Configured data paths must remain under the project root") from exc
    return resolved


class Settings(BaseSettings):
    """Validated runtime settings shared by API, workers, and migrations."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: str = (
        "postgresql+psycopg://guardian:guardian_dev_only@127.0.0.1:5432/guardian"
    )
    workspace_root: Path = Path("data/workspaces")
    scan_output_root: Path = Path("data/scans")
    max_repository_size_mb: PositiveInt = 200
    max_file_count: PositiveInt = 30_000
    max_manifest_size_mb: PositiveInt = 8
    max_artifact_size_mb: PositiveInt = 100
    git_clone_timeout_seconds: PositiveInt = 120
    syft_timeout_seconds: PositiveInt = 120
    osv_enabled: bool = True
    osv_timeout_seconds: PositiveInt = 20
    grype_enabled: bool = True
    grype_timeout_seconds: PositiveInt = 180
    nvd_enabled: bool = True
    nvd_api_key: SecretStr | None = None
    nvd_timeout_seconds: PositiveInt = 20
    nvd_budget_seconds: PositiveInt = 1200
    nvd_cache_days: PositiveInt = 7
    nvd_cache_root: Path = Path("data/nvd")
    # Optional AI analyst (off by default). The key is read from the environment only.
    ai_enabled: bool = False
    ai_provider: str = "groq"  # "groq" (default), "xai" (Grok) or "anthropic" (Claude)
    ai_model: str | None = None  # unset: the provider's default model
    groq_api_key: SecretStr | None = None
    xai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    ai_effort: str | None = None  # provider reasoning effort; unset uses the provider default
    ai_timeout_seconds: PositiveInt = 120
    ai_wall_clock_seconds: PositiveInt = 300
    ai_max_output_tokens: PositiveInt | None = None  # unset: provider default
    ai_max_tool_result_chars: PositiveInt | None = None  # unset: provider default
    ai_tool_budget: PositiveInt = 5
    ai_external_budget: int = 2
    ai_external_timeout_seconds: PositiveInt = 15
    max_active_scans: PositiveInt = 1
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65_535)
    frontend_origin: str = "http://localhost:3000"
    log_level: str = "INFO"

    @field_validator("workspace_root", "scan_output_root", "nvd_cache_root", mode="after")
    @classmethod
    def resolve_data_path(cls, value: Path) -> Path:
        return _resolve_project_path(value)


settings = Settings()

