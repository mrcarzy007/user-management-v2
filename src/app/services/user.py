from app.core.security import hash_password
from app.repositories.user import UserRepository


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def create(self, email: str, password: str):
        hashed_password = hash_password(password)

        user = await self.user_repo.create(
            email=email,
            hashed_password=hashed_password,
        )

        return user

    async def get_by_email(self, email: str):
        return await self.user_repo.get_by_email(email)
