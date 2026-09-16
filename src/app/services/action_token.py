from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.security import generate_action_token, compute_token_hash
from app.core.settings import settings
from app.models.action_token import TokenType
from app.repositories.action_token import ActionTokenRepository


class ActionTokenService:
    def __init__(self, action_token_repo: ActionTokenRepository):
        self.action_token_repo = action_token_repo

    async def create(
        self, user_id: int, token_type: TokenType, payload: dict[str, Any] | None = None
    ):

        raw_token, token_hash = generate_action_token()

        expires_at = datetime.now(tz=UTC) + timedelta(
            minutes=settings.ACTION_TOKEN_EXPIRE_MINUTES
        )

        await self.action_token_repo.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            token_type=token_type,
            payload=payload,
        )

        return raw_token

    async def verify(self, token_type: TokenType, token: str) -> None:

        token_hash = compute_token_hash(token)

        await self.action_token_repo.verify(
            token_hash=token_hash, token_type=token_type
        )
