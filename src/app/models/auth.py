from pydantic import BaseModel, EmailStr

from .user import UserResponse


class AuthRegister(BaseModel):
    email: EmailStr
    password: str


class AuthToken(BaseModel):
    email: EmailStr
    password: str


class AuthRegisterResponse(BaseModel):
    user: UserResponse
    access_token: str
    refresh_token: str


class AuthTokenResponse(BaseModel):
    user: UserResponse
    access_token: str
    refresh_token: str
    type: str
