from psycopg import AsyncConnection

from app.core.security import hash_password
from app.repositories.user import UserRepository


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def create(
        self, email: str, password: str, db_conn: AsyncConnection | None = None
    ):
        hashed_password = hash_password(password)

        user = await self.user_repo.create(
            email=email,
            hashed_password=hashed_password,
            db_conn=db_conn,
        )

        return user

    async def update_password(
        self, user_id: int, password: str, db_conn: AsyncConnection | None = None
    ):
        hashed_password = hash_password(password)

        user = await self.user_repo.update_user(
            user_id=user_id,
            hashed_password=hashed_password,
            db_conn=db_conn,
        )

        return user

    async def get_by_email(self, email: str, db_conn: AsyncConnection | None = None):
        return await self.user_repo.get_by_email(email, db_conn=db_conn)

    async def get_by_id(self, user_id: int, db_conn: AsyncConnection | None = None):
        return await self.user_repo.get_by_id(user_id, db_conn=db_conn)

    async def verify_email(self, user_id: int, db_conn: AsyncConnection | None = None):
        return await self.user_repo.update_user(
            user_id=user_id, is_verified=True, db_conn=db_conn
        )
