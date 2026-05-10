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
    student_email_allowlist: str = Field(
        default="spc7p@umsystem.edu,sgwwp@umsystem.edu,ts8md@umsystem.edu,bayd6@umsystem.edu",
        validation_alias="STUDENT_EMAIL_ALLOWLIST",
    )
    otp_expire_seconds: int = Field(default=300, validation_alias="OTP_EXPIRE_SECONDS")
    # demo -> return/log OTP (no email). smtp -> send real email via SMTP.
    otp_delivery_mode: str = Field(default="demo", validation_alias="OTP_DELIVERY_MODE")
    smtp_host: str = Field(default="", validation_alias="SMTP_HOST")
    smtp_port: int = Field(default=587, validation_alias="SMTP_PORT")
    smtp_username: str = Field(default="", validation_alias="SMTP_USERNAME")
    smtp_password: str = Field(default="", validation_alias="SMTP_PASSWORD")
    smtp_from_email: str = Field(default="", validation_alias="SMTP_FROM_EMAIL")
    smtp_use_starttls: bool = Field(default=True, validation_alias="SMTP_USE_STARTTLS")
    # For demo/testing only. Keep false in production; OTP stays email-only.
    expose_otp_in_response: bool = Field(default=True, validation_alias="EXPOSE_OTP_IN_RESPONSE")

    def db_file(self) -> Path:
        if self.database_path is not None:
            return Path(self.database_path)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "voting.db"

    def allowed_student_emails(self) -> set[str]:
        raw = (self.student_email_allowlist or "").strip()
        if raw.startswith("\ufeff"):
            raw = raw[1:]
        return {
            e.strip().lower()
            for e in raw.split(",")
            if e.strip()
        }


settings = Settings()
