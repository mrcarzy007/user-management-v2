from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from fastapi.responses import Response

from app.core.security import create_access_token, verify_password
from app.dependencies import get_session_service, get_user_service
from app.models.auth import AuthRegister, AuthToken, AuthTokenResponse
from app.services.session import SessionService
from app.services.user import UserService

router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
)


def set_refresh_token_cookie(
    res: Response, raw_refresh_token: str, expires_at: datetime
):
    remaining_seconds = int((expires_at - datetime.now(tz=UTC)).total_seconds())

    # Ensure max_age isn't negative if the session expired right before execution
    max_age = max(0, remaining_seconds)

    res.set_cookie(
        key="refresh_token",
        value=raw_refresh_token,
        max_age=max_age,
        secure=True,
        httponly=True,
        samesite="strict",
    )


@router.post(
    "/register",
    response_model=AuthTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    res: Response,
    data: AuthRegister,
    user_service: Annotated[UserService, Depends(get_user_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    request: Request,
):

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

    return {"access_token": access_token, "type": "Bearer"}


@router.post("/token", response_model=AuthTokenResponse, status_code=status.HTTP_200_OK)
async def token(
    res: Response,
    data: AuthToken,
    user_service: Annotated[UserService, Depends(get_user_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    request: Request,
):

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

    set_refresh_token_cookie(
        res=res,
        raw_refresh_token=raw_refresh_token,
        expires_at=session.expires_at,
    )

    access_token = create_access_token(user_id=user.id)

    return {
        "access_token": access_token,
        "type": "Bearer",
    }


@router.post(
    "/refresh", response_model=AuthTokenResponse, status_code=status.HTTP_200_OK
)
async def refresh(
    res: Response,
    session_service: Annotated[SessionService, Depends(get_session_service)],
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token cookie missing",
        )

    raw_refresh_token, session = await session_service.update_refresh_token(
        raw_refresh_token=refresh_token
    )

    set_refresh_token_cookie(
        res=res,
        raw_refresh_token=raw_refresh_token,
        expires_at=session.expires_at,
    )

    access_token = create_access_token(user_id=session.user_id)

    return {
        "access_token": access_token,
        "type": "Bearer",
    }


@router.post("/logout")
def logout(): ...


@router.post("/logout-all")
def logout_all(): ...


@router.post("/me")
def me(): ...


@router.post("/verify-email")
def verify_email(): ...


@router.post("/forgot-password")
def forgot_password(): ...


@router.post("/reset-password")
def reset_password(): ...
