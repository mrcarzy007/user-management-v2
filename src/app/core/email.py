from httpx import AsyncClient

from app.core.settings import settings


async def send_email(
    to: list[str],
    subject: str,
    text: str,
):
    async with AsyncClient() as client:
        res = await client.post(
            "https://send.api.mailtrap.io/api/send",
            headers={
                "Authorization": f"Bearer {settings.MAILTRAP_API_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "from": {
                    "email": settings.NO_REPLY_EMAIL,
                    "name": settings.APP_NAME,
                },
                "to": [{"email": email} for email in to],
                "subject": subject,
                "text": text,
            },
        )

    if not res.status_code == 200:
        raise RuntimeError(f"Failed to send email to {to!r} with subject {subject!r}")
