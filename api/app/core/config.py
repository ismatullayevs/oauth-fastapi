from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal
from pathlib import Path


class Settings(BaseSettings):
    app_name: str = "Awesome API"
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    ENVIRONMENT: Literal["development",
                         "production", "testing"] = "development"
    SECRET_KEY: str = "insecure-secret-key"
    ALGORITHM: str = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    MAILGUN_API_TOKEN: str = ""
    EMAIL_API: str = ""

    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = ""
    GOOGLE_AUTH_URL: str = f"https://accounts.google.com/o/oauth2/auth"

    def get_google_auth_url(self) -> str:
        return f"{self.GOOGLE_AUTH_URL}?client_id={self.GOOGLE_CLIENT_ID}&response_type=code&scope=openid%20email%20profile&redirect_uri={self.GOOGLE_REDIRECT_URI}"
     
    APP_URL: str = "http://localhost:5000"
    API_URL: str = "http://localhost:8000"

    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env")


settings = Settings()
