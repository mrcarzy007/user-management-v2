from typing import Annotated

from fastapi import Depends, Request
from psycopg_pool import AsyncConnectionPool

from app.repositories.user import UserRepository
from app.services.user import UserService


def get_db_pool(req: Request) -> AsyncConnectionPool:
    pool = req.app.state.pool

    if not isinstance(pool, AsyncConnectionPool):
        raise TypeError("Pool must be type of AsyncConnectionPool")

    return pool


async def get_user_service(
    pool: Annotated[AsyncConnectionPool, Depends(get_db_pool)],
) -> UserService:

    return UserService(repo=UserRepository(pool))
