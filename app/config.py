"""Application settings loaded from environment variables."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_name: str = "GCP FastAPI"
    api_base_url: str = "http://localhost:8000"  # Used for OAuth redirect URIs

    # JWT
    secret_key: str = "change-me-in-production-use-openssl-rand-hex-32"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24 * 7  # 7 days

    # OAuth – Google
    google_client_id: str = ""
    google_client_secret: str = ""

    # OAuth – GitHub
    github_client_id: str = ""
    github_client_secret: str = ""

    # OAuth – Apple (Sign in with Apple)
    apple_client_id: str = ""
    apple_team_id: str = ""
    apple_key_id: str = ""
    apple_private_key: str = ""  # PEM content or path; for simplicity use env with escaped newlines or file path

    # Email (optional – for magic links)
    sendgrid_api_key: str = ""
    from_email: str = "noreply@example.com"


settings = Settings()
