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
    public_host: str | None = None
    destination: str | None = None
    splunk_hec_url: str | None = None
    splunk_hec_token: str | None = None
    splunk_index: str | None = None
    splunk_sourcetype: str = "fusion_siem:v1"
    qradar_host: str | None = None
    qradar_port: int = 514
    rapid7_url: str | None = None
    rapid7_token: str | None = None
