from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FUSION_SIEM_",
        env_file=".env",
        extra="ignore",
    )

    ingest_token: str = Field(min_length=1)
    data_dir: Path = Path("data")
    forward_url: str | None = None
    forward_token: str | None = None
    host: str = "0.0.0.0"
    port: int = 8080
