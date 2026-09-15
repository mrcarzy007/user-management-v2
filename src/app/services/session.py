from datetime import UTC, datetime, timedelta

from fastapi import Request

from app.core.security import compute_token_hash, generate_refresh_token
from app.core.settings import settings
from app.repositories.session import SessionRepository


def extract_client_info(request: Request) -> tuple[str | None, str | None]:
    """helper to safely extract device_info and ip_address from HTTP headers."""

    device_info = request.headers.get("User-Agent")
    x_forwarded_for = request.headers.get("X-Forwarded-For")

    ip_address: str | None

    if x_forwarded_for:
        ip_address = x_forwarded_for.split(",")[0].strip()
    else:
        ip_address = request.client.host if request.client else None

    return device_info, ip_address


class SessionService:
    def __init__(self, session_repo: SessionRepository):
        self.session_repo = session_repo

    async def create(self, name: str | None, user_id: int, request: Request):

        raw_refresh_token, refresh_token_hash = generate_refresh_token()

        expires_at = datetime.now(tz=UTC) + timedelta(
            minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
        )

        device_info, ip_address = extract_client_info(request)

        session = await self.session_repo.create(
            name=name,
            user_id=user_id,
            device_info=device_info,
            ip_address=ip_address,
            expires_at=expires_at,
            token_hash=refresh_token_hash,
        )

        return raw_refresh_token, session

    async def update_refresh_token(self, raw_refresh_token: str):
        old_token_hash = compute_token_hash(raw_refresh_token)

        new_raw_refresh_token, new_token_hash = generate_refresh_token()

        new_expires_at = datetime.now(tz=UTC) + timedelta(
            minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
        )

        return await self.session_repo.update_refresh_token(
            old_token_hash=old_token_hash,
            new_raw_refresh_token=new_raw_refresh_token,
            new_token_hash=new_token_hash,
            new_expires_at=new_expires_at,
        )
