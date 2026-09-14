from fastapi import HTTPException, status
from psycopg.errors import UniqueViolation

from app.core.security import encode_jwt_token, hash_password, verify_password
from app.models.auth import AuthRegister, AuthToken
from app.models.user import User
from app.repositories.user import UserRepository


class AuthService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def register(self, data: AuthRegister) -> User:
        hashed_password = hash_password(data.password)

        try:
            return await self.user_repo.create(
                email=data.email,
                hashed_password=hashed_password,
            )
        except UniqueViolation as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"User with {data.email!r} already exists.",
            ) from e

    async def token(self, data: AuthToken):
        user = await self.user_repo.get_by_email(email=data.email)

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Credentials.",
            )

        if not verify_password(
            plain_password=data.password,
            hashed_password=user.hashed_password,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Credentials.",
            )

        token = encode_jwt_token(user_id=user.id, token_type="short")

        return {"token": token, "type": "Bearer"}
