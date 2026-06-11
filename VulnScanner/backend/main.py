"""FastAPI application entry point."""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI

# Load .env from backend directory
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
else:
    _env_example = Path(__file__).parent / ".env.example"
    if _env_example.exists():
        load_dotenv(_env_example)

from .api.middleware.security import setup_security
from .api.routes.health import router as health_router
from .api.routes.history import router as history_router
from .api.routes.scan import router as scan_router
from .api.routes.github import router as github_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Code Vulnerability Scanner",
        description="Production-grade static analysis vulnerability scanner with LLM-powered reporting",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Setup security middleware
    allowed_origins = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")
    setup_security(app, allowed_origins=allowed_origins.split(","))

    # Register routes
    app.include_router(health_router)
    app.include_router(scan_router)
    app.include_router(history_router)
    app.include_router(github_router)

    @app.on_event("startup")
    async def startup():
        logger.info("Code Vulnerability Scanner API starting up...")

    return app


app = create_app()
