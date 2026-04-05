from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env from the repo root so admin credentials load even if uvicorn's cwd is elsewhere.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_dir: Path = Field(
        default=Path(__file__).resolve().parent.parent / "data",
        validation_alias="DATA_DIR",
    )
    database_path: Path | None = Field(default=None, validation_alias="DATABASE_PATH")

    jwt_secret: str = "change-me-in-production-use-long-random-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    admin_password: str = "admin-change-me"
    admin_username: str = "admin"
    # When true, on each app start the admin named ADMIN_USERNAME gets password hash from ADMIN_PASSWORD (fixes .env vs old DB mismatch).
    sync_admin_from_env: bool = Field(default=True, validation_alias="SYNC_ADMIN_FROM_ENV")

    election_starts_at: str | None = None
    election_ends_at: str | None = None

    def db_file(self) -> Path:
        if self.database_path is not None:
            return Path(self.database_path)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "voting.db"


settings = Settings()
