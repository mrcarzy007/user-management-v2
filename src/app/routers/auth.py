from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.dependencies import get_user_service
from app.models.user import User, UserCreate, UserResponse
from app.services.user import UserService

router = APIRouter(
    prefix="/auth",
    tags=["Tags"],
)


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register(
    data: UserCreate, user_service: Annotated[UserService, Depends(get_user_service)]
) -> User:
    return await user_service.create(data)


@router.post("/token")
def token(): ...


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
