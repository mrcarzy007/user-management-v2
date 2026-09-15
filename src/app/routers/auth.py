from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from psycopg.errors import UniqueViolation

from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.dependencies import get_session_repo, get_user_repo
from app.models.auth import (
    AuthRegister,
    AuthRegisterResponse,
    AuthToken,
    AuthTokenResponse,
)
from app.repositories.session import SessionRepository
from app.repositories.user import UserRepository

router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
)


def extract_client_info(request: Request) -> tuple[str | None, str | None]:
    """helper to safely extract device_info and ip_address from HTTP headers."""

    device_info = request.headers.get("User-Agent")
    x_forwarded_for = request.headers.get("X-Forwarded-For")

    ip_address: str | None

    if x_forwarded_for:
        ip_address = x_forwarded_for.split(",")[0].strip()
    else:
        ip_address = request.client.host if request.client else None

    return device_info, ip_address


@router.post(
    "/register",
    response_model=AuthRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    data: AuthRegister,
    user_repo: Annotated[UserRepository, Depends(get_user_repo)],
    session_repo: Annotated[SessionRepository, Depends(get_session_repo)],
    request: Request,
):
    hashed_password = hash_password(data.password)

    try:
        user = await user_repo.create(
            email=data.email,
            hashed_password=hashed_password,
        )
    except UniqueViolation as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with {data.email!r} already exists.",
        ) from e

    device_info, ip_address = extract_client_info(request)

    raw_refresh_token, _ = await session_repo.create(
        name=None,
        user_id=user.id,
        device_info=device_info,
        ip_address=ip_address,
    )

    access_token = create_access_token(user_id=user.id)

    return {
        "user": user,
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
    }


@router.post("/token", response_model=AuthTokenResponse, status_code=status.HTTP_200_OK)
async def token(
    data: AuthToken,
    user_repo: Annotated[UserRepository, Depends(get_user_repo)],
    session_repo: Annotated[SessionRepository, Depends(get_session_repo)],
    request: Request,
):
    user = await user_repo.get_by_email(email=data.email)

    if user is None or not verify_password(
        plain_password=data.password,
        hashed_password=user.hashed_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    device_info, ip_address = extract_client_info(request)

    raw_refresh_token, _ = await session_repo.create(
        name=None,
        user_id=user.id,
        device_info=device_info,
        ip_address=ip_address,
    )

    access_token = create_access_token(user_id=user.id)

    return {
        "user": user,
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
        "type": "Bearer",
    }


@router.post("/refresh")
def refresh(): ...


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
