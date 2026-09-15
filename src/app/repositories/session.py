from datetime import datetime

from psycopg.rows import class_row
from psycopg_pool import AsyncConnectionPool

from app.core.exceptions import InvalidTokenError
from app.models.session import Session


class SessionRepository:
    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def create(
        self,
        user_id: int,
        token_hash: str,
        expires_at: datetime,
        name: str | None,
        device_info: str | None,
        ip_address: str | None,
    ):

        async with (
            self.pool.connection() as conn,
            conn.cursor(row_factory=class_row(Session)) as cur,
        ):
            await cur.execute(
                t"""
                    INSERT INTO refresh_tokens ( name, user_id, token_hash, expires_at, device_info, ip_address ) 
                    VALUES ( {name}, {user_id}, {token_hash}, {expires_at}, {device_info}, {ip_address} )
                    RETURNING *
                """
            )

            session = await cur.fetchone()

            if session is None:
                raise RuntimeError("Failed to create session")

            return session

    async def update_refresh_token(
        self,
        old_token_hash: str,
        new_raw_refresh_token: str,
        new_token_hash: str,
        new_expires_at: datetime,
    ) -> tuple[str, Session]:

        async with (
            self.pool.connection() as conn,
            conn.cursor(row_factory=class_row(Session)) as cur,
        ):
            await cur.execute(
                t"""
                UPDATE refresh_tokens
                SET token_hash = {new_token_hash}, expires_at = {new_expires_at}
                WHERE token_hash = {old_token_hash} AND expires_at > CURRENT_TIMESTAMP
                RETURNING *
                """
            )

            updated_session = await cur.fetchone()

            if updated_session is None:
                raise InvalidTokenError("Invalid or expired refresh token")

            return new_raw_refresh_token, updated_session
