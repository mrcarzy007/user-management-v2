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
