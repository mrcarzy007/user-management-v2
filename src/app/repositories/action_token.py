from datetime import datetime
from typing import Any

from psycopg.rows import class_row
from psycopg_pool import AsyncConnectionPool

from app.core.exceptions import InvalidTokenError
from app.models.action_token import ActionToken, TokenType


class ActionTokenRepository:
    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def create(
        self,
        user_id: int,
        token_hash: str,
        token_type: TokenType,
        expires_at: datetime,
        payload: dict[str, Any] | None = None,
    ) -> ActionToken:
        async with (
            self.pool.connection() as conn,
            conn.cursor(row_factory=class_row(ActionToken)) as cur,
        ):
            await cur.execute(
                t"""
                INSERT INTO user_action_tokens
                (user_id, token_hash, token_type, payload, expires_at)
                Values ({user_id}, {token_hash}, {token_type}, {payload}, {expires_at})
                RETURNING *
                """,
            )

            action_token = await cur.fetchone()

            if action_token is None:
                raise RuntimeError("Failed to create user action token")

            return action_token

    async def verify(self, token_hash: str, token_type: str) -> None:
        async with (
            self.pool.connection() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                t"""
                DELETE FROM user_action_tokens
                WHERE token_hash = {token_hash} AND token_type = {token_type} AND expires_at > CURRENT_TIMESTAMP
                RETURNING *;
                """,
            )

            action_token = await cur.fetchone()

            if action_token is None:
                raise InvalidTokenError("Invalid or expired action token")
