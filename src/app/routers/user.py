from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.dependencies import get_current_user, get_user_service
from app.models.auth import PasswordChange
from app.models.user import User, UserResponse
from app.services.user import UserService

router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


def clear_auth_cookies(res: Response) -> None:
    res.delete_cookie(
        "access_token", secure=True, httponly=True, samesite="strict", path="/"
    )
    res.delete_cookie(
        "refresh_token", secure=True, httponly=True, samesite="strict", path="/"
    )


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    return current_user


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_me(
    res: Response,
    current_user: Annotated[User, Depends(get_current_user)],
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> None:
    await user_service.delete(user_id=current_user.id)
    clear_auth_cookies(res)


@router.patch("/me/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    data: PasswordChange,
    current_user: Annotated[User, Depends(get_current_user)],
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> None:
    await user_service.change_password(
        user_id=current_user.id,
        current_password=data.current_password,
        new_password=data.new_password,
    )