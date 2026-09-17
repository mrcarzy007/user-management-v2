from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import AsyncConnection

from app.core.exceptions import TokenCooldownError
from app.core.security import compute_token_hash, generate_action_token
from app.core.settings import settings
from app.models.action_token import TokenType
from app.models.user import User
from app.repositories.action_token import ActionTokenRepository


class ActionTokenService:
    def __init__(self, action_token_repo: ActionTokenRepository):
        self.action_token_repo = action_token_repo

    async def lock_user(
        self, user_id: int, db_conn: AsyncConnection | None = None
    ) -> None:
        await self.action_token_repo.lock_user(user_id=user_id, db_conn=db_conn)

    async def create(
        self,
        user: User,
        token_type: TokenType,
        payload: dict[str, Any] | None = None,
    ):
        async with self.action_token_repo.pool.connection() as conn:
            await self.lock_user(user_id=user.id, db_conn=conn)

            await self.enforce_cooldown_period(
                token_type=token_type,
                current_user=user,
                db_conn=conn,
            )

            await self.revoke_all_by_user(
                user_id=user.id,
                token_type=token_type,
                db_conn=conn,
            )

            raw_token, token_hash = generate_action_token()

            expires_at = datetime.now(tz=UTC) + timedelta(
                minutes=settings.ACTION_TOKEN_EXPIRE_MINUTES
            )

            await self.action_token_repo.create(
                user_id=user.id,
                token_hash=token_hash,
                expires_at=expires_at,
                token_type=token_type,
                payload=payload,
                db_conn=conn,
            )

            return raw_token

    async def consume(
        self, token_type: TokenType, token: str, db_conn: AsyncConnection | None = None
    ):

        token_hash = compute_token_hash(token)

        return await self.action_token_repo.consume(
            token_hash=token_hash, token_type=token_type, db_conn=db_conn
        )

    async def revoke(
        self, token_type: TokenType, token: str, db_conn: AsyncConnection | None = None
    ) -> None:
        await self.action_token_repo.revoke(
            token_hash=compute_token_hash(token), token_type=token_type, db_conn=db_conn
        )

    async def revoke_all_by_user(
        self,
        user_id: int,
        token_type: TokenType,
        db_conn: AsyncConnection | None = None,
    ) -> None:
        await self.action_token_repo.revoke_all_by_user(
            user_id=user_id, token_type=token_type, db_conn=db_conn
        )

    async def get_latest_token(
        self,
        user_id: int,
        token_type: TokenType,
        db_conn: AsyncConnection | None = None,
    ):
        return await self.action_token_repo.get_latest_token(
            user_id=user_id, token_type=token_type, db_conn=db_conn
        )

    async def enforce_cooldown_period(
        self,
        current_user: User,
        db_conn: AsyncConnection,
        token_type: TokenType,
    ):

        latest_token = await self.get_latest_token(
            user_id=current_user.id,
            token_type=token_type,
            db_conn=db_conn,
        )

        if latest_token is not None:
            created_at = latest_token.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            elapsed = (datetime.now(tz=UTC) - created_at).total_seconds()
            if elapsed < settings.ACTION_TOKEN_COOLDOWN_SECONDS:
                remaining = int(settings.ACTION_TOKEN_COOLDOWN_SECONDS - elapsed)
                raise TokenCooldownError(
                    f"Please wait {remaining} seconds before requesting a new verification email."
                )
