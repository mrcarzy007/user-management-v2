from datetime import datetime, timedelta
from typing import Literal
from zoneinfo import ZoneInfo

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.settings import settings

password_hasher = PasswordHash([Argon2Hasher()])


def hash_password(plain_password: str) -> str:
    return password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hasher.verify(
        password=plain_password,
        hash=hashed_password,
    )


def encode_jwt_token(user_id: int, token_type: Literal["short", "long"]) -> str:

    if token_type != "short" and token_type != "long":
        raise ValueError("Invalid token type")

    expire = datetime.now(tz=ZoneInfo("UTC")) + timedelta(
        minutes=settings.SHORT_TOKEN_DURATION_IN_MINUTES
        if token_type == "short"
        else settings.LONG_TOKEN_DURATION_IN_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "expire": expire.isoformat(),
    }

    token = jwt.encode(
        payload=payload,
        key=settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

    return token
