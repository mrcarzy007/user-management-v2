from typing import Annotated

from fastapi import Depends, Request
from psycopg_pool import AsyncConnectionPool

from app.repositories.session import SessionRepository
from app.repositories.user import UserRepository


def get_db_pool(req: Request) -> AsyncConnectionPool:
    pool = req.app.state.pool

    if not isinstance(pool, AsyncConnectionPool):
        raise TypeError("Pool must be type of AsyncConnectionPool")

    return pool


def get_user_repo(
    pool: Annotated[AsyncConnectionPool, Depends(get_db_pool)],
) -> UserRepository:
    return UserRepository(pool=pool)


def get_session_repo(
    pool: Annotated[AsyncConnectionPool, Depends(get_db_pool)],
) -> SessionRepository:
    return SessionRepository(pool=pool)
