from psycopg.errors import UniqueViolation
from psycopg.rows import class_row
from psycopg_pool import AsyncConnectionPool

from app.core.exceptions import DuplicateRecordError, RecordNotFoundError
from app.models.user import User


class UserRepository:
    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def create(self, email: str, hashed_password: str) -> User:
        try:
            async with (
                self.pool.connection() as conn,
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

    async def get_by_email(self, email: str) -> User:

        async with (
            self.pool.connection() as conn,
            conn.cursor(row_factory=class_row(User)) as cur,
        ):
            await cur.execute(t"""SELECT * FROM users WHERE email = LOWER({email})""")

            user = await cur.fetchone()

            if user is None:
                raise RecordNotFoundError("User not found")

            return user
