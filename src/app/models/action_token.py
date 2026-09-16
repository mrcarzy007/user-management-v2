from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class TokenType(StrEnum):
    email_verification = "email_verification"


@dataclass
class ActionToken:
    id: int
    user_id: int
    token_hash: str
    token_type: TokenType
    payload: Any
    expires_at: datetime
    created_at: datetime
