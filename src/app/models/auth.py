from pydantic import BaseModel, EmailStr


class AuthRegister(BaseModel):
    email: EmailStr
    password: str


class AuthToken(BaseModel):
    email: EmailStr
    password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str
