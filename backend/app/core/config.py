from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # "production" enables environment-aware hardening (e.g. HSTS). Set via ENVIRONMENT env var.
    environment: str = "development"

    # If set, local filesystem scan paths (see app/api/routes/scans.py) must resolve inside this
    # directory — closes off scanning arbitrary server paths via the `path` scan parameter. Left
    # unset by default for MVP/local-dev convenience; set it in any deployment where the backend
    # host also holds data that authenticated users should not be able to point a scan at.
    scan_root_dir: str | None = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
