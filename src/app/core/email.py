import asyncio

import mailtrap as mt

from app.core.settings import settings

client = mt.MailtrapClient(settings.MAILTRAP_API_TOKEN)
sending_api = client.sending_api


def send_email(
    to: list[str],
    subject: str,
    text: str,
):
    mail = mt.Mail(
        sender=mt.Address(email=settings.NO_REPLY_EMAIL, name=settings.APP_NAME),
        to=[mt.Address(email=email) for email in to],
        subject=subject,
        text=text,
    )

    res = sending_api.send(mail)

    if not res.success:
        raise RuntimeError(f"Failed to send email to {to!r} with subject {subject!r}")


async def send_email_in_thread(**kwargs):
    await asyncio.to_thread(send_email, **kwargs)
