from fastapi import APIRouter

from .action_tokens import router as action_tokens_router
from .auth import router as auth_router
from .session import router as session_router
from .user import router as user_router

router = APIRouter()

router.include_router(auth_router)
router.include_router(action_tokens_router)
router.include_router(session_router)
router.include_router(user_router)
