from httpx import AsyncClient


async def test_register_user_input_validation(client: AsyncClient):
    res = await client.post(
        "/auth/register",
        headers={"Content-Type": "application/json"},
        json={
            "email": "user@.com",
        },
    )

    assert res.status_code == 422


async def test_register_user(client: AsyncClient):
    res = await client.post(
        "/auth/register",
        headers={"Content-Type": "application/json"},
        json={
            "email": "user@email.com",
            "password": "123456",
        },
    )

    assert res.status_code == 201

    data = res.json()

    assert data["is_active"] == False
    assert data["is_verified"] == False
    assert data["email"] == "user@email.com"


async def test_register_duplicate_user(client: AsyncClient):
    res = await client.post(
        "/auth/register",
        headers={"Content-Type": "application/json"},
        json={
            "email": "user@email.com",
            "password": "123456",
        },
    )

    assert res.status_code == 201

    res = await client.post(
        "/auth/register",
        headers={"Content-Type": "application/json"},
        json={
            "email": "user@email.com",
            "password": "123456",
        },
    )

    assert res.status_code == 409


async def test_token(client: AsyncClient):

    user = {
        "email": "user@email.com",
        "password": "123456",
    }

    res = await client.post(
        "/auth/register",
        headers={"Content-Type": "application/json"},
        json=user,
    )

    assert res.status_code == 201

    res = await client.post(
        "/auth/token",
        headers={"Content-Type": "application/json"},
        json=user,
    )

    assert res.status_code == 200

    data = res.json()

    assert "token" in data
    assert data["type"] == "Bearer"
