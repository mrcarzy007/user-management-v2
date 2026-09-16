from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from fastapi.responses import Response

from app.core.exceptions import InvalidTokenError
from app.core.security import create_access_token, verify_password
from app.core.settings import settings
from app.dependencies import get_current_user, get_session_service, get_user_service
from app.models.auth import AuthRegister, AuthToken
from app.models.session import SessionResponse
from app.models.user import User, UserResponse
from app.services.session import SessionService
from app.services.user import UserService

router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
)

ACCESS_TOKEN_COOKIE_NAME = "access_token"
REFRESH_TOKEN_COOKIE_NAME = "refresh_token"


def set_access_token_cookie(res: Response, access_token: str):
    max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # 60 seconds * minutes

    res.set_cookie(
        key=ACCESS_TOKEN_COOKIE_NAME,
        value=access_token,
        max_age=max_age,
        secure=True,
        httponly=True,
        samesite="strict",
    )


def set_refresh_token_cookie(
    res: Response, raw_refresh_token: str, expires_at: datetime
):
    remaining_seconds = int((expires_at - datetime.now(tz=UTC)).total_seconds())

    # Ensure max_age isn't negative if the session expired right before execution
    max_age = max(0, remaining_seconds)

    res.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=raw_refresh_token,
        max_age=max_age,
        secure=True,
        httponly=True,
        samesite="strict",
    )


@router.post("/register", status_code=status.HTTP_204_NO_CONTENT)
async def register(
    res: Response,
    data: AuthRegister,
    user_service: Annotated[UserService, Depends(get_user_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    request: Request,
) -> None:

    user = await user_service.create(email=data.email, password=data.password)

    raw_refresh_token, session = await session_service.create(
        name=None,
        user_id=user.id,
        request=request,
    )

    set_refresh_token_cookie(
        res=res,
        raw_refresh_token=raw_refresh_token,
        expires_at=session.expires_at,
    )

    access_token = create_access_token(user_id=user.id)

    set_access_token_cookie(res, access_token)


@router.post("/token", status_code=status.HTTP_204_NO_CONTENT)
async def token(
    res: Response,
    data: AuthToken,
    user_service: Annotated[UserService, Depends(get_user_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    request: Request,
    refresh_token: Annotated[str | None, Cookie()] = None,
) -> None:

    user = await user_service.get_by_email(email=data.email)

    if not verify_password(
        plain_password=data.password,
        hashed_password=user.hashed_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_refresh_token, session = await session_service.create(
        name=None,
        user_id=user.id,
        request=request,
    )

    if refresh_token is not None:
        await session_service.logout(user_id=user.id, refresh_token=refresh_token)

    set_refresh_token_cookie(
        res=res,
        raw_refresh_token=raw_refresh_token,
        expires_at=session.expires_at,
    )

    access_token = create_access_token(user_id=user.id)

    set_access_token_cookie(res, access_token)


@router.get("/refresh", status_code=status.HTTP_204_NO_CONTENT)
async def refresh(
    res: Response,
    session_service: Annotated[SessionService, Depends(get_session_service)],
    refresh_token: Annotated[str, Cookie()],
) -> None:

    raw_refresh_token, session = await session_service.update_refresh_token(
        refresh_token=refresh_token
    )

    set_refresh_token_cookie(
        res=res,
        raw_refresh_token=raw_refresh_token,
        expires_at=session.expires_at,
    )

    access_token = create_access_token(user_id=session.user_id)

    set_access_token_cookie(res, access_token)


@router.get("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    res: Response,
    session_service: Annotated[SessionService, Depends(get_session_service)],
    refresh_token: Annotated[str, Cookie()],
    current_user: Annotated[User, Depends(get_current_user)],
) -> None:
    await session_service.logout(user_id=current_user.id, refresh_token=refresh_token)

    res.delete_cookie(
        ACCESS_TOKEN_COOKIE_NAME, secure=True, httponly=True, samesite="strict"
    )
    res.delete_cookie(
        REFRESH_TOKEN_COOKIE_NAME, secure=True, httponly=True, samesite="strict"
    )


@router.get("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    res: Response,
    session_service: Annotated[SessionService, Depends(get_session_service)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> None:
    await session_service.logout_all(user_id=current_user.id)

    res.delete_cookie(
        ACCESS_TOKEN_COOKIE_NAME, secure=True, httponly=True, samesite="strict"
    )
    res.delete_cookie(
        REFRESH_TOKEN_COOKIE_NAME, secure=True, httponly=True, samesite="strict"
    )


@router.get("", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
):
    return current_user


@router.get(
    "/sessions/current", response_model=SessionResponse, status_code=status.HTTP_200_OK
)
async def get_current_session(
    current_user: Annotated[User, Depends(get_current_user)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    refresh_token: Annotated[str, Cookie()],
):
    sessions = await session_service.get_sessions(
        user_id=current_user.id, refresh_token=refresh_token
    )

    if not sessions:
        raise InvalidTokenError("Invalid or expired refresh token")

    return sessions[0]


@router.get(
    "/sessions", response_model=list[SessionResponse], status_code=status.HTTP_200_OK
)
async def get_all_sessions(
    current_user: Annotated[User, Depends(get_current_user)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
):
    return await session_service.get_sessions(
        user_id=current_user.id, refresh_token=None
    )


@router.post("/verify-email")
def verify_email(): ...


@router.post("/forgot-password")
def forgot_password(): ...


@router.post("/reset-password")
def reset_password(): ...
