"""
Конфигурация приложения. Секреты и настройки загружаются из переменных окружения.
Используется pydantic-settings с поддержкой .env через python-dotenv.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Настройки из переменных окружения (в т.ч. из .env)."""
    secret_key: str = "change-in-production"
    database_url: str = "sqlite:///./app.db"
    jwt_algorithm: str = "HS256"
    jwt_expire_hours: int = 48

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
