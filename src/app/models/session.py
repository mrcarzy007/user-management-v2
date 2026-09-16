from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel


@dataclass
class Session:
    id: int
    name: str | None
    user_id: int
    token_hash: str
    expires_at: datetime
    device_info: str | None
    ip_address: str | None
    created_at: datetime
    updated_at: datetime


class SessionResponse(BaseModel):
    id: int
    name: str | None
    user_id: int
    device_info: str | None
    ip_address: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
