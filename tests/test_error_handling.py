from httpx import AsyncClient
from psycopg_pool import PoolTimeout
from pytest import MonkeyPatch

from app.main import app


async def test_db_connection_error_handling(
    client: AsyncClient, monkeypatch: MonkeyPatch
):

    def mock_connection(*args, **kwargs):
        raise PoolTimeout("Could not acquire connection within timeout")

    monkeypatch.setattr(app.state.pool, "connection", mock_connection)

    res = await client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "123456"},
    )

    assert res.status_code == 500
