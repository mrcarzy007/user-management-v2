from app.core.email import send_email
from app.core.settings import settings
from app.models.action_token import TokenType
from app.services.action_token import ActionTokenService


async def send_verification_email(
    action_token_service: ActionTokenService,
    email: str,
    raw_token: str,
) -> None:
    try:
        await send_email(
            to=[email],
            subject=f"Verify Your Email —— {settings.APP_NAME}",
            text=f"""
            Hello,

            Please click below link to verify your email.
            {settings.BASE_URL.rstrip("/")}/auth/verify-email?token={raw_token}

            If you did not request this verification, please ignore this email.
            """,
        )

    except Exception:  # noqa: BLE001
        await action_token_service.revoke(
            token_type=TokenType.email_verification, token=raw_token
        )


async def send_forgot_password_email(
    action_token_service: ActionTokenService,
    email: str,
    raw_token: str,
) -> None:
    try:
        await send_email(
            to=[email],
            subject=f"Reset Your Password —— {settings.APP_NAME}",
            text=f"""
            Hello,

            Please click below link to reset your password.
            {settings.BASE_URL.rstrip("/")}/auth/reset-password?token={raw_token}

            If you did not request this verification, please ignore this email.
            """,
        )

    except Exception:  # noqa: BLE001
        await action_token_service.revoke(
            token_type=TokenType.password_reset, token=raw_token
        )


async def send_change_email_verification(
    action_token_service: ActionTokenService,
    email: str,
    raw_token: str,
) -> None:
    try:
        await send_email(
            to=[email],
            subject=f"Verif Your New Email —— {settings.APP_NAME}",
            text=f"""
            Hello,

            Please click below link to update your email.
            {settings.BASE_URL.rstrip("/")}/auth/verify-new-email?token={raw_token}

            If you did not request this verification, please ignore this email.
            """,
        )

    except Exception:  # noqa: BLE001
        await action_token_service.revoke(
            token_type=TokenType.email_change, token=raw_token
        )
