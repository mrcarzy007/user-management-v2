from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: str
    SHORT_TOKEN_DURATION_IN_MINUTES: int
    LONG_TOKEN_DURATION_IN_MINUTES: int
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str


settings = Settings()  # pyright: ignore[reportCallIssue]
