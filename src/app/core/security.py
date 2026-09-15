import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.settings import settings

password_hasher = PasswordHash([Argon2Hasher()])


def hash_password(plain_password: str) -> str:
    return password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hasher.verify(password=plain_password, hash=hashed_password)


def create_access_token(user_id: int) -> str:
    """Generates a short-lived (15-minute) stateless JWT access token."""

    now = datetime.now(tz=UTC)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": expire.timestamp(),
        "type": "access",
    }

    return jwt.encode(
        payload=payload,
        key=settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_access_token(access_token: str):
    try:
        payload = jwt.decode(
            access_token,
            key=settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

        return int(payload["sub"])
    except jwt.exceptions.PyJWTError:
        return


def generate_action_token(nbytes: int = 32) -> tuple[str, str]:
    """Generates a short-lived single-use action token (Verification / Reset)."""

    raw_token = secrets.token_urlsafe(nbytes)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def generate_refresh_token(nbytes: int = 64) -> tuple[str, str]:
    """Generates a long-lived persistent session refresh token (30-90 days)."""

    raw_token = secrets.token_urlsafe(nbytes)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def compute_token_hash(raw_token: str) -> str:
    """Computes SHA-256 hex digest of an incoming raw token string for DB lookup."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def verify_hashes(hash_a: str, hash_b: str) -> bool:
    """Compares two hash strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(hash_a, hash_b)
