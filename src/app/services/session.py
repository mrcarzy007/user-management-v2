from datetime import UTC, datetime, timedelta

from app.core.security import generate_refresh_token
from app.core.settings import settings
from app.repositories.session import SessionRepository


class SessionService:
    def __init__(self, session_repo: SessionRepository):
        self.session_repo = session_repo

    async def create(
        self,
        session_name,
        user_id,
        device_info,
        ip_address,
    ):
        raw_token, token_hash = generate_refresh_token()

        expires_at = datetime.now(tz=UTC) + timedelta(
            minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
        )

        session = await self.session_repo.create(
            session_name=session_name,
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )

        return session, raw_token
