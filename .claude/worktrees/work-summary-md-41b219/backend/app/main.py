"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError

from app.api.errors import register_exception_handlers
from app.api.routes.scans import router as scans_router
from app.config import settings
from app.database.scans import reconcile_interrupted_scans
from app.database.session import session_factory

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    try:
        with session_factory() as db:
            interrupted = reconcile_interrupted_scans(db)
        if interrupted:
            logger.warning("marked %d interrupted scans as failed", interrupted)
    except SQLAlchemyError:
        logger.warning("database unavailable during startup reconciliation")
    yield

app = FastAPI(
    title="Software Supply Chain Guardian",
    version="0.1.0",
    description="Phase 1 dependency inventory and graph API",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
register_exception_handlers(app)
app.include_router(scans_router, prefix="/api/v1")


@app.get("/api/v1/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}

