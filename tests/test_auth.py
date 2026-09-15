from httpx import AsyncClient


async def test_auth_register_input_validation(client: AsyncClient):
    res = await client.post(
        "/auth/register",
        headers={"Content-Type": "application/json"},
        json={
            "email": "user@.com",
        },
    )

    assert res.status_code == 422


async def test_auth_register(client: AsyncClient):
    res = await client.post(
        "/auth/register",
        headers={"Content-Type": "application/json"},
        json={
            "email": "user@email.com",
            "password": "123456",
        },
    )

    assert res.status_code == 201

    assert res.cookies.get("access_token") is not None
    assert res.cookies.get("refresh_token") is not None


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


async def test_auth_token(client: AsyncClient):

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

    assert res.cookies.get("access_token") is not None
    assert res.cookies.get("refresh_token") is not None


async def test_auth_refresh(client: AsyncClient):

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

    access_token = res.cookies.get("access_token")
    refresh_token = res.cookies.get("refresh_token")

    assert access_token is not None
    assert refresh_token is not None

    client.cookies.clear()

    client.cookies["refresh_token"] = refresh_token

    res = await client.post("/auth/refresh")

    assert res.status_code == 200

    assert res.cookies.get("access_token") is not None
    assert res.cookies.get("refresh_token") is not None
    assert res.cookies.get("access_token") != access_token
    assert res.cookies.get("refresh_token") != refresh_token


async def test_auth_logout(client: AsyncClient):

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

    access_token = res.cookies.get("access_token")
    refresh_token = res.cookies.get("refresh_token")

    assert access_token is not None
    assert refresh_token is not None

    client.cookies.clear()

    client.cookies["access_token"] = access_token
    client.cookies["refresh_token"] = refresh_token

    res = await client.get("/auth/logout")

    assert res.status_code == 200

    assert res.cookies.get("access_token") is None
    assert res.cookies.get("refresh_token") is None
