from fastapi import HTTPException, status
from psycopg.errors import UniqueViolation

from app.core.security import hash_password
from app.models.user import User, UserCreate
from app.repositories.user import UserRepository


class UserService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    async def create(self, data: UserCreate) -> User:
        hashed_password = hash_password(data.password)

        try:
            return await self.repo.create(
                email=data.email, hashed_password=hashed_password
            )
        except UniqueViolation as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"User with {data.email!r} already exists.",
            ) from e
