from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv


@dataclass(slots=True)
class Settings:
    client_id: str
    client_secret: str
    base_url: str | None = None
    default_repository: str = "search-all"
    default_lookback: str = "1d"
    ngsiem_poll_interval: float = 2.0
    ngsiem_timeout_seconds: int = 60
    rtr_timeout_seconds: int = 60
    rtr_queue_offline: bool = False


class ConfigurationError(RuntimeError):
    """Raised when required environment variables are missing."""


def load_settings(env_path: str | os.PathLike[str] | None = None) -> Settings:
    """Load settings from environment variables and an optional .env file."""
    if env_path:
        load_dotenv(dotenv_path=Path(env_path), override=False)
    else:
        load_dotenv(override=False)

    client_id = os.getenv("FALCON_CLIENT_ID", "").strip()
    client_secret = os.getenv("FALCON_CLIENT_SECRET", "").strip()
    base_url = os.getenv("FALCON_BASE_URL", "").strip() or None

    if not client_id or not client_secret:
        raise ConfigurationError(
            "FALCON_CLIENT_ID / FALCON_CLIENT_SECRET belum terisi. "
            "Salin .env.example menjadi .env lalu isi credential Anda."
        )

    return Settings(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        default_repository=os.getenv("FALCON_DEFAULT_REPOSITORY", "search-all").strip() or "search-all",
        default_lookback=os.getenv("FALCON_DEFAULT_LOOKBACK", "1d").strip() or "1d",
        ngsiem_poll_interval=float(os.getenv("FALCON_NGSIEM_POLL_INTERVAL", "2")),
        ngsiem_timeout_seconds=int(os.getenv("FALCON_NGSIEM_TIMEOUT_SECONDS", "60")),
        rtr_timeout_seconds=int(os.getenv("FALCON_RTR_TIMEOUT_SECONDS", "60")),
        rtr_queue_offline=os.getenv("FALCON_RTR_QUEUE_OFFLINE", "false").strip().lower() in {"1", "true", "yes", "y"},
    )
