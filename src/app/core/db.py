from contextlib import asynccontextmanager

from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool


@asynccontextmanager
async def get_db_conn(
    pool: AsyncConnectionPool,
    conn: AsyncConnection | None = None,
):

    if conn is not None:
        yield conn
    else:
        async with pool.connection() as pool_conn:
            yield pool_conn
