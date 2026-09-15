import subprocess

import pytest
from httpx import ASGITransport, AsyncClient
from psycopg_pool import AsyncConnectionPool

from app.main import app


@pytest.fixture(scope="session", autouse=True)
def test_db():
    test_db_url = "postgres://postgres:postgres@postgres:5432/test_db?sslmode=disable"

    process = subprocess.run(
        ["dbmate", "--url", test_db_url, "-d", "./migrations", "up"],
        check=True,
    )

    assert process.returncode == 0

    return test_db_url


@pytest.fixture(scope="session", autouse=True)
async def db_pool(test_db: str):

    pool = AsyncConnectionPool(test_db, open=False)
    await pool.open()

    app.state.pool = pool

    yield pool
    await pool.close()


@pytest.fixture(scope="function")
async def client(db_pool: AsyncConnectionPool):
    async with db_pool.connection() as conn:
        await conn.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE;")
        await conn.execute("TRUNCATE TABLE refresh_tokens RESTART IDENTITY CASCADE;")

    transport = ASGITransport(app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
