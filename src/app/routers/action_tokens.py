from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Body, Depends, status
from psycopg_pool import AsyncConnectionPool
from pydantic import EmailStr

from app.background_tasks import send_forgot_password_email, send_verification_email
from app.core.exceptions import EmailAlreadyVerifiedError
from app.dependencies import (
    get_action_token_service,
    get_current_user,
    get_db_pool,
    get_user_service,
)
from app.models.action_token import TokenType
from app.models.user import User
from app.services.action_token import ActionTokenService
from app.services.user import UserService

router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
)

ACCESS_TOKEN_COOKIE_NAME = "access_token"
REFRESH_TOKEN_COOKIE_NAME = "refresh_token"


@router.post("/verify-email/send", status_code=status.HTTP_202_ACCEPTED)
async def verify_email_send(
    current_user: Annotated[User, Depends(get_current_user)],
    action_token_service: Annotated[
        ActionTokenService, Depends(get_action_token_service)
    ],
    background_tasks: BackgroundTasks,
) -> None:
    if current_user.is_verified:
        raise EmailAlreadyVerifiedError("Email is already verified")

    raw_token = await action_token_service.create(
        token_type=TokenType.email_verification, user=current_user
    )

    background_tasks.add_task(
        send_verification_email,
        action_token_service,
        current_user.email,
        raw_token,
    )


@router.post("/verify-email", status_code=status.HTTP_204_NO_CONTENT)
async def verify_email(
    action_token_service: Annotated[
        ActionTokenService, Depends(get_action_token_service)
    ],
    pool: Annotated[AsyncConnectionPool, Depends(get_db_pool)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    token: str,
) -> None:
    async with pool.connection() as conn:
        user_id = await action_token_service.consume(
            token=token,
            token_type=TokenType.email_verification,
            db_conn=conn,
        )

        await user_service.verify_email(db_conn=conn, user_id=user_id)


@router.post("/password-reset/send")
async def password_reset_send(
    email: Annotated[EmailStr, Body()],
    user_service: Annotated[UserService, Depends(get_user_service)],
    action_token_service: Annotated[
        ActionTokenService, Depends(get_action_token_service)
    ],
    background_tasks: BackgroundTasks,
) -> None:

    user = await user_service.get_by_email(email)

    raw_token = await action_token_service.create(
        token_type=TokenType.password_reset, user=user
    )

    background_tasks.add_task(
        send_forgot_password_email,
        action_token_service,
        user.email,
        raw_token,
    )


@router.post("/password-reset")
async def password_reset(
    password: Annotated[str, Body()],
    action_token_service: Annotated[
        ActionTokenService, Depends(get_action_token_service)
    ],
    pool: Annotated[AsyncConnectionPool, Depends(get_db_pool)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    token: str,
) -> None:
    async with pool.connection() as conn:
        user_id = await action_token_service.consume(
            token=token,
            token_type=TokenType.password_reset,
            db_conn=conn,
        )

        await user_service.update_password(
            user_id=user_id,
            db_conn=conn,
            password=password,
        )
