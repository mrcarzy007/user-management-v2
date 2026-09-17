from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient, Response

USER = {"email": "user@email.com", "password": "123456"}


def assert_auth_cookies(response: Response):
    cookies = response.cookies
    assert cookies.get("access_token")
    assert cookies.get("refresh_token")

    set_cookie_headers = response.headers.get_list("set-cookie")

    assert len(set_cookie_headers) == 2
    for header in set_cookie_headers:
        assert "Secure" in header
        assert "HttpOnly" in header
        assert "SameSite=strict" in header
        assert "Max-Age=" in header


async def register(client: AsyncClient, user: dict = USER):
    response = await client.post("/auth/register", json=user)
    assert response.status_code == 204
    assert response.content == b""
    assert_auth_cookies(response)
    return response.cookies.get("access_token"), response.cookies.get("refresh_token")


def use_tokens(
    client: AsyncClient, access_token: str | None, refresh_token: str | None
):
    client.cookies.clear()
    if access_token is not None:
        client.cookies["access_token"] = access_token
    if refresh_token is not None:
        client.cookies["refresh_token"] = refresh_token


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"email": "user@.com", "password": "123456"},
        {"email": "user@email.com"},
        {"email": "not-an-email", "password": "123456"},
    ],
)
async def test_register_rejects_invalid_input(client: AsyncClient, payload: dict):
    response = await client.post("/auth/register", json=payload)

    assert response.status_code == 422


async def test_register_creates_user_and_secure_session_cookies(client: AsyncClient):
    await register(client)


async def test_register_rejects_duplicate_email(client: AsyncClient):
    await register(client)

    response = await client.post("/auth/register", json=USER)

    assert response.status_code == 409
    assert response.json() == {"detail": "User with 'user@email.com' already exists."}


async def test_token_issues_a_new_session(client: AsyncClient):
    old_access_token, old_refresh_token = await register(client)

    response = await client.post("/auth/token", json=USER)

    assert response.status_code == 204
    assert_auth_cookies(response)
    assert response.cookies.get("access_token") != old_access_token
    assert response.cookies.get("refresh_token") != old_refresh_token


@pytest.mark.parametrize(
    "user, expected_status, expected_detail",
    [
        ({"email": USER["email"], "password": "wrong"}, 401, "Invalid Credentials"),
        (
            {"email": "missing@email.com", "password": USER["password"]},
            404,
            "User not found",
        ),
    ],
)
async def test_token_rejects_invalid_credentials(
    client: AsyncClient, user: dict, expected_status: int, expected_detail: str
):
    await register(client)

    response = await client.post("/auth/token", json=user)

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}


async def test_refresh_rotates_token_and_rejects_replay(client: AsyncClient):
    access_token, refresh_token = await register(client)
    use_tokens(client, None, refresh_token)

    response = await client.get("/auth/refresh")

    assert response.status_code == 204
    assert_auth_cookies(response)
    assert response.cookies.get("access_token") != access_token
    assert response.cookies.get("refresh_token") != refresh_token

    use_tokens(client, None, refresh_token)
    replay = await client.get("/auth/refresh")
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid or expired refresh token"}


async def test_refresh_requires_a_valid_cookie(client: AsyncClient):
    missing = await client.get("/auth/refresh")
    assert missing.status_code == 422

    client.cookies["refresh_token"] = "invalid"
    invalid = await client.get("/auth/refresh")
    assert invalid.status_code == 401
    assert invalid.json() == {"detail": "Invalid or expired refresh token"}


async def test_get_me_returns_public_user_fields(client: AsyncClient):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)

    response = await client.get("/auth/me")

    assert response.status_code == 200
    assert response.json()["email"] == USER["email"]
    assert "hashed_password" not in response.json()


def extract_verification_token(email_text: str) -> str:
    return email_text.split("token=")[1].split()[0]


async def test_verify_email_is_single_use(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)

    sent_emails = []

    async def record_email(**kwargs):
        sent_emails.append((kwargs["to"], kwargs["subject"], kwargs["text"]))

    monkeypatch.setattr("app.routers.auth.send_email_in_thread", record_email)

    response = await client.post("/auth/verify-email/send")
    assert response.status_code == 202
    assert len(sent_emails) == 1
    raw_token = extract_verification_token(sent_emails[0][2])

    replay = await client.post("/auth/verify-email", params={"token": raw_token})
    assert replay.status_code == 204

    user = await client.get("/auth/me")
    assert user.json()["is_verified"] is True

    second_attempt = await client.post(
        "/auth/verify-email", params={"token": raw_token}
    )
    assert second_attempt.status_code == 401
    assert second_attempt.json() == {"detail": "Invalid or expired action token"}


async def test_protected_routes_reject_missing_and_invalid_access_tokens(
    client: AsyncClient,
):
    missing = await client.get("/auth/me")
    assert missing.status_code == 422

    client.cookies["access_token"] = "invalid"
    invalid = await client.get("/auth/me")
    assert invalid.status_code == 401
    assert invalid.json() == {"detail": "Invalid or expired access token"}


async def test_current_session_hides_token_hash(client: AsyncClient):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)

    response = await client.get("/auth/sessions/me")

    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == 1
    assert data["device_info"] == "python-httpx/0.28.1"
    assert data["ip_address"] == "127.0.0.1"
    assert "token_hash" not in data


async def test_current_session_rejects_unknown_refresh_token(client: AsyncClient):
    access_token, _ = await register(client)
    use_tokens(client, access_token, "invalid")

    response = await client.get("/auth/sessions/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired refresh token"}


async def test_all_sessions_lists_only_the_current_users_sessions(client: AsyncClient):
    access_token, _ = await register(client)
    use_tokens(client, access_token, None)
    token_response = await client.post("/auth/token", json=USER)
    use_tokens(
        client,
        token_response.cookies.get("access_token"),
        token_response.cookies.get("refresh_token"),
    )

    response = await client.get("/auth/sessions")

    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) == 2
    assert all("token_hash" not in session for session in sessions)


async def test_logout_revokes_only_the_selected_session(client: AsyncClient):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, None)
    token_response = await client.post("/auth/token", json=USER)
    second_refresh_token = token_response.cookies.get("refresh_token")
    second_access_token = token_response.cookies.get("access_token")
    use_tokens(client, second_access_token, second_refresh_token)

    response = await client.get("/auth/logout")

    assert response.status_code == 204
    assert response.headers.get_list("set-cookie")

    use_tokens(client, None, refresh_token)
    assert (await client.get("/auth/refresh")).status_code == 204
    use_tokens(client, None, second_refresh_token)
    assert (await client.get("/auth/refresh")).status_code == 401


async def test_logout_all_revokes_every_session(client: AsyncClient):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)
    token_response = await client.post("/auth/token", json=USER)
    second_refresh_token = token_response.cookies.get("refresh_token")
    second_access_token = token_response.cookies.get("access_token")
    use_tokens(client, second_access_token, second_refresh_token)

    response = await client.get("/auth/logout-all")

    assert response.status_code == 204
    use_tokens(client, None, refresh_token)
    assert (await client.get("/auth/refresh")).status_code == 401
    use_tokens(client, None, second_refresh_token)
    assert (await client.get("/auth/refresh")).status_code == 401


async def test_verify_email_with_query_token(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)

    sent_emails = []

    async def record_email(**kwargs):
        sent_emails.append((kwargs["to"], kwargs["subject"], kwargs["text"]))

    monkeypatch.setattr("app.routers.auth.send_email_in_thread", record_email)

    response = await client.post("/auth/verify-email/send")
    assert response.status_code == 202
    assert len(sent_emails) == 1
    raw_token = extract_verification_token(sent_emails[0][2])

    verify = await client.post("/auth/verify-email", params={"token": raw_token})
    assert verify.status_code == 204

    user = await client.get("/auth/me")
    assert user.json()["is_verified"] is True

    replay = await client.post("/auth/verify-email", params={"token": raw_token})
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid or expired action token"}


async def test_verify_email_rejects_missing_token(client: AsyncClient):
    response = await client.post("/auth/verify-email")
    assert response.status_code == 422


async def test_verify_email_send_success_and_cooldown(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)

    sent_emails = []

    async def record_email(**kwargs):
        sent_emails.append((kwargs["to"], kwargs["subject"], kwargs["text"]))

    monkeypatch.setattr("app.routers.auth.send_email_in_thread", record_email)

    response = await client.post("/auth/verify-email/send")
    assert response.status_code == 202
    assert len(sent_emails) == 1

    resend = await client.post("/auth/verify-email/send")
    assert resend.status_code == 429
    assert "Please wait" in resend.json()["detail"]


async def test_verify_email_send_rejects_already_verified_user(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)

    sent_emails = []

    async def record_email(**kwargs):
        sent_emails.append((kwargs["to"], kwargs["subject"], kwargs["text"]))

    monkeypatch.setattr("app.routers.auth.send_email_in_thread", record_email)

    send = await client.post("/auth/verify-email/send")
    assert send.status_code == 202
    token = extract_verification_token(sent_emails[0][2])

    verify = await client.post("/auth/verify-email", params={"token": token})
    assert verify.status_code == 204

    response = await client.post("/auth/verify-email/send")
    assert response.status_code == 400
    assert response.json() == {"detail": "Email is already verified"}


async def test_verify_email_send_revokes_token_when_email_fails(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)

    async def fail_to_send(**kwargs):
        raise RuntimeError("email provider unavailable")

    monkeypatch.setattr("app.routers.auth.send_email_in_thread", fail_to_send)

    first = await client.post("/auth/verify-email/send")
    assert first.status_code == 202

    sent_emails = []

    async def record_email(**kwargs):
        sent_emails.append((kwargs["to"], kwargs["subject"], kwargs["text"]))

    monkeypatch.setattr("app.routers.auth.send_email_in_thread", record_email)
    second = await client.post("/auth/verify-email/send")
    assert second.status_code == 202
    assert len(sent_emails) == 1


async def test_verify_email_send_revokes_previous_token(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
):
    access_token, refresh_token = await register(client)
    use_tokens(client, access_token, refresh_token)

    sent_emails = []

    async def record_email(**kwargs):
        sent_emails.append((kwargs["to"], kwargs["subject"], kwargs["text"]))

    monkeypatch.setattr("app.routers.auth.send_email_in_thread", record_email)

    response1 = await client.post("/auth/verify-email/send")
    assert response1.status_code == 202
    assert len(sent_emails) == 1
    token1 = extract_verification_token(sent_emails[0][2])

    class FutureDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            base = datetime.now(tz=UTC) + timedelta(minutes=3)
            if tz is not None:
                return base.astimezone(tz)
            return base.replace(tzinfo=None)

    monkeypatch.setattr("app.routers.auth.datetime", FutureDatetime)

    response2 = await client.post("/auth/verify-email/send")
    assert response2.status_code == 202
    assert len(sent_emails) == 2
    token2 = extract_verification_token(sent_emails[1][2])
    assert token1 != token2

    verify_first = await client.post("/auth/verify-email", params={"token": token1})
    assert verify_first.status_code == 401
    assert verify_first.json() == {"detail": "Invalid or expired action token"}

    verify_second = await client.post("/auth/verify-email", params={"token": token2})
    assert verify_second.status_code == 204

    user = await client.get("/auth/me")
    assert user.json()["is_verified"] is True
