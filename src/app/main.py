from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from psycopg_pool import AsyncConnectionPool

from app.core.exceptions import (
    DuplicateRecordError,
    InvalidTokenError,
    RecordNotFoundError,
)
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


@app.exception_handler(InvalidTokenError)
async def invalid_token_exception_handler(request: Request, exc: InvalidTokenError):
    """Maps domain token errors to HTTP 401 Unauthorized responses."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": exc.message},
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(RecordNotFoundError)
async def record_not_found_exception_handler(
    request: Request, exc: RecordNotFoundError
):
    """Maps missing domain record errors to HTTP 404 Not Found responses."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": exc.message},
    )


@app.exception_handler(DuplicateRecordError)
async def duplicate_record_exception_handler(
    request: Request, exc: DuplicateRecordError
):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": exc.message},
    )
