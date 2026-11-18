from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", enable_decoding=False)

    app_env: str = "development"
    database_url: str = "sqlite:///./app.db"
    jwt_secret: str = "development-only-secret-change-before-production"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 14
    refresh_cookie_secure: bool = False
    allowed_origins: list[str] = ["http://localhost:3000"]

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    def validate_for_startup(self) -> None:
        if self.app_env == "production":
            if len(self.jwt_secret) < 32 or self.jwt_secret.startswith("development-"):
                raise RuntimeError("JWT_SECRET must be a random value of at least 32 characters")
            if not self.refresh_cookie_secure:
                raise RuntimeError("REFRESH_COOKIE_SECURE must be true in production")


@lru_cache
def get_settings() -> Settings:
    return Settings()
