from datetime import datetime
from typing import Any

from psycopg import AsyncConnection
from psycopg.rows import class_row
from psycopg_pool import AsyncConnectionPool

from app.core.db import get_db_conn
from app.core.exceptions import InvalidTokenError
from app.models.action_token import ActionToken, TokenType


class ActionTokenRepository:
    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def lock_user(
        self, user_id: int, db_conn: AsyncConnection | None = None
    ) -> None:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(t"SELECT pg_advisory_xact_lock(1, {user_id})")

    async def create(
        self,
        user_id: int,
        token_hash: str,
        token_type: TokenType,
        expires_at: datetime,
        payload: dict[str, Any] | None = None,
        db_conn: AsyncConnection | None = None,
    ) -> ActionToken:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
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

    async def consume(
        self, token_hash: str, token_type: str, db_conn: AsyncConnection | None = None
    ) -> int:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor(row_factory=class_row(ActionToken)) as cur,
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

            return action_token.user_id

    async def revoke(
        self,
        token_hash: str,
        token_type: TokenType,
        db_conn: AsyncConnection | None = None,
    ) -> None:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                t"""
                DELETE FROM user_action_tokens
                WHERE token_hash = {token_hash} AND token_type = {token_type}
                """
            )

    async def revoke_all_by_user(
        self,
        user_id: int,
        token_type: TokenType,
        db_conn: AsyncConnection | None = None,
    ) -> None:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                t"""
                DELETE FROM user_action_tokens
                WHERE user_id = {user_id} AND token_type = {token_type}
                """
            )

    async def get_latest_token(
        self,
        user_id: int,
        token_type: TokenType,
        db_conn: AsyncConnection | None = None,
    ) -> ActionToken | None:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor(row_factory=class_row(ActionToken)) as cur,
        ):
            await cur.execute(
                t"""
                SELECT * FROM user_action_tokens
                WHERE user_id = {user_id} AND token_type = {token_type}
                ORDER BY created_at DESC
                LIMIT 1
                """
            )
            return await cur.fetchone()
