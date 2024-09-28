from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    app_name: str = "Awesome API"
    SECRET_KEY: str = "<SECRET-KEY>"
    ALGORITHM: str = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    MAILGUN_API_TOKEN: str = "<API-TOKEN>"
    
    APP_URL: str = "http://localhost:3000"
    API_URL: str = "http://localhost:8000"

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache()
def get_settings():
    return Settings()
