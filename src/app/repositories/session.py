from datetime import datetime

from psycopg import AsyncConnection, sql
from psycopg.rows import class_row
from psycopg_pool import AsyncConnectionPool

from app.core.db import get_db_conn
from app.core.exceptions import InvalidTokenError, RecordNotFoundError
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
        db_conn: AsyncConnection | None = None,
    ):

        async with (
            get_db_conn(self.pool, db_conn) as conn,
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

    async def get_sessions(
        self, user_id: int, token_hash: str | None = None
    ) -> list[Session]:
        filters = []

        if token_hash is not None:
            filters.append(t"token_hash = {token_hash}")

        query = sql.SQL(", ").join(filters) if filters else sql.SQL("TRUE")

        async with (
            self.pool.connection() as conn,
            conn.cursor(row_factory=class_row(Session)) as cur,
        ):
            await cur.execute(
                t"""
                SELECT * FROM refresh_tokens
                WHERE user_id = {user_id} AND {query:q}
                """
            )

            sessions = await cur.fetchall()

            return sessions

    async def delete_session(
        self,
        user_id: int,
        token_hash: str,
        db_conn: AsyncConnection | None = None,
    ) -> None:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor(row_factory=class_row(Session)) as cur,
        ):
            await cur.execute(
                t"""
                DELETE FROM refresh_tokens 
                WHERE token_hash = {token_hash} AND user_id = {user_id} 
                RETURNING *
                """
            )

            session = await cur.fetchone()

            if session is None:
                raise InvalidTokenError("Invalid or expired refresh token")

    async def delete_all_sessions(self, user_id: int) -> None:
        async with (
            self.pool.connection() as conn,
            conn.cursor(row_factory=class_row(Session)) as cur,
        ):
            await cur.execute(
                t"""
                DELETE FROM refresh_tokens 
                WHERE user_id = {user_id} 
                RETURNING *
                """
            )

            if cur.rowcount <= 0:
                raise RecordNotFoundError("No sessions found")
