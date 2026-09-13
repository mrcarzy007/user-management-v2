from contextlib import asynccontextmanager

from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from app.core.settings import settings
from app.routers import router as all_routers


@asynccontextmanager
async def lifespan(app: FastAPI):
    pool = AsyncConnectionPool(settings.DATABASE_URL, open=False)
    await pool.open()
    app.state.pool = pool
    yield
    await pool.close()


app = FastAPI(lifespan=lifespan)

app.include_router(all_routers)
