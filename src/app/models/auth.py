from pydantic import BaseModel, EmailStr


class AuthRegister(BaseModel):
    email: EmailStr
    password: str


class AuthToken(BaseModel):
    email: EmailStr
    password: str


class AuthTokenResponse(BaseModel):
    access_token: str
    type: str
