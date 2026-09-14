from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.dependencies import get_auth_service
from app.models.auth import (
    AuthRegister,
    AuthRegisterResponse,
    AuthToken,
    AuthTokenResponse,
)
from app.services.auth import AuthService

router = APIRouter(
    prefix="/auth",
    tags=["Tags"],
)


@router.post(
    "/register",
    response_model=AuthRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    data: AuthRegister,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
):
    return await auth_service.register(data)


@router.post("/token", response_model=AuthTokenResponse, status_code=status.HTTP_200_OK)
async def token(
    data: AuthToken,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
):
    return await auth_service.token(data)


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
