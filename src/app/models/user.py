from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel


@dataclass
class User:
    id: int
    email: str
    hashed_password: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime


class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
