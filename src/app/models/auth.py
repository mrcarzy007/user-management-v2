from datetime import datetime

from pydantic import BaseModel, EmailStr


class AuthRegister(BaseModel):
    email: EmailStr
    password: str


class AuthToken(BaseModel):
    email: EmailStr
    password: str


class AuthRegisterResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime


class AuthTokenResponse(BaseModel):
    token: str
    type: str
