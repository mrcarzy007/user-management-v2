from dataclasses import dataclass
from datetime import datetime


@dataclass
class Session:
    id: int
    name: str
    user_id: int
    token_hash: str
    expires_at: datetime
    device_info: str
    ip_address: str
    created_at: datetime
    updated_at: datetime
