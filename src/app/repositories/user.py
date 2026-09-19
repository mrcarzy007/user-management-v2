from psycopg import AsyncConnection, sql
from psycopg.errors import UniqueViolation
from psycopg.rows import class_row
from psycopg_pool import AsyncConnectionPool

from app.core.db import get_db_conn
from app.core.exceptions import DuplicateRecordError, RecordNotFoundError
from app.models.user import User


class UserRepository:
    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def create(
        self, email: str, hashed_password: str, db_conn: AsyncConnection | None = None
    ) -> User:
        try:
            async with (
                get_db_conn(self.pool, db_conn) as conn,
                conn.cursor(row_factory=class_row(User)) as cur,
            ):
                await cur.execute(
                    t"""
                        INSERT INTO users (email,hashed_password,is_active,is_verified) 
                        VALUES ({email}, {hashed_password}, {False}, {False})
                        RETURNING *
                    """
                )

                created_user = await cur.fetchone()

                if created_user is None:
                    raise RuntimeError("UserRepository: Failed to create user")

                return created_user
        except UniqueViolation as e:
            raise DuplicateRecordError(f"User with {email!r} already exists.") from e

    async def update_user(
        self,
        user_id: int,
        email: str | None = None,
        hashed_password: str | None = None,
        is_active: bool | None = None,
        is_verified: bool | None = None,
        db_conn: AsyncConnection | None = None,
    ) -> User:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor(row_factory=class_row(User)) as cur,
        ):
            fields = []

            if email is not None:
                fields.append(t"email = {email}")
            if hashed_password is not None:
                fields.append(t"hashed_password = {hashed_password}")
            if is_active is not None:
                fields.append(t"is_active = {is_active}")
            if is_verified is not None:
                fields.append(t"is_verified = {is_verified}")

            set_clause = sql.SQL(", ").join(fields)

            await cur.execute(
                t"""
                UPDATE users
                SET {set_clause:q}
                WHERE id = {user_id}
                RETURNING *
                """,
            )

            updated_user = await cur.fetchone()

            if updated_user is None:
                raise RecordNotFoundError("User not found")

            return updated_user

    async def delete(self, user_id: int, db_conn: AsyncConnection | None = None) -> None:
        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                t"""
                DELETE FROM users
                WHERE id = {user_id}
                """
            )

            if cur.rowcount <= 0:
                raise RecordNotFoundError("User not found")

    async def get_by_email(
        self, email: str, db_conn: AsyncConnection | None = None
    ) -> User:

        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor(row_factory=class_row(User)) as cur,
        ):
            await cur.execute(t"""SELECT * FROM users WHERE email = LOWER({email})""")

            user = await cur.fetchone()

            if user is None:
                raise RecordNotFoundError("User not found")

            return user

    async def get_by_id(
        self, user_id: int, db_conn: AsyncConnection | None = None
    ) -> User:

        async with (
            get_db_conn(self.pool, db_conn) as conn,
            conn.cursor(row_factory=class_row(User)) as cur,
        ):
            await cur.execute(t"""SELECT * FROM users WHERE id = {user_id}""")

            user = await cur.fetchone()

            if user is None:
                raise RecordNotFoundError("User not found")

            return user
