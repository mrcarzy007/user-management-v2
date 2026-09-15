from datetime import UTC, datetime, timedelta

from psycopg.rows import class_row
from psycopg_pool import AsyncConnectionPool

from app.core.security import generate_refresh_token
from app.core.settings import settings
from app.models.session import Session


class SessionRepository:
    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def create(
        self,
        user_id: int,
        name: str | None,
        device_info: str | None,
        ip_address: str | None,
    ):
        raw_refresh_token, refresh_token_hash = generate_refresh_token()

        expires_at = datetime.now(tz=UTC) + timedelta(
            minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
        )

        async with (
            self.pool.connection() as conn,
            conn.cursor(row_factory=class_row(Session)) as cur,
        ):
            await cur.execute(
                t"""
                    INSERT INTO refresh_tokens ( name, user_id, token_hash, expires_at, device_info, ip_address ) 
                    VALUES ( {name}, {user_id}, {refresh_token_hash}, {expires_at}, {device_info}, {ip_address} )
                    RETURNING *
                """
            )

            session = await cur.fetchone()

            if session is None:
                raise RuntimeError("Failed to create session")

            return raw_refresh_token, session
