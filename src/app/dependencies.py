from typing import Annotated

from fastapi import Cookie, Depends, Request
from psycopg_pool import AsyncConnectionPool

from app.core.exceptions import InvalidTokenError
from app.core.security import decode_access_token
from app.repositories.session import SessionRepository
from app.repositories.user import UserRepository
from app.services.session import SessionService
from app.services.user import UserService


def get_db_pool(req: Request) -> AsyncConnectionPool:
    pool = req.app.state.pool

    if not isinstance(pool, AsyncConnectionPool):
        raise TypeError("Pool must be type of AsyncConnectionPool")

    return pool


def get_user_service(
    pool: Annotated[AsyncConnectionPool, Depends(get_db_pool)],
) -> UserService:
    return UserService(user_repo=UserRepository(pool=pool))


def get_session_service(
    pool: Annotated[AsyncConnectionPool, Depends(get_db_pool)],
) -> SessionService:
    return SessionService(session_repo=SessionRepository(pool=pool))


async def get_current_user(
    access_token: Annotated[str, Cookie()],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
    user_id = decode_access_token(access_token)

    if user_id is None:
        raise InvalidTokenError("Invalid or expired access token")

    user = await user_service.get_by_id(user_id)

    return user
