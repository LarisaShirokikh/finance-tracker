"""
Main FastAPI application for Finance Tracker

This module initializes the FastAPI application, configures CORS,
registers routers, and sets up middleware.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import logging

from app.api import auth
from app.api.v1.endpoints import categories
from app.core.config import settings, get_cors_origins

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events
    """
    # Startup
    logger.info("=" * 50)
    logger.info(f"Starting {settings.project_name}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"API prefix: {settings.api_v1_prefix}")
    logger.info(f"Keycloak URL: {settings.keycloak_url}")
    logger.info(f"Keycloak Realm: {settings.keycloak_realm}")
    logger.info(f"CORS origins: {get_cors_origins()}")
    logger.info("=" * 50)

    yield

    # Shutdown
    logger.info("Shutting down Finance Tracker...")


def create_application() -> FastAPI:
    """
    Application factory for creating FastAPI instance

    This factory pattern allows:
    - Creating app with different settings for tests
    - Better control over initialization
    - Easier testing
    """

    app = FastAPI(
        title=settings.project_name,
        description="Personal finance tracking system with OAuth authentication",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url=f"{settings.api_v1_prefix}/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
    )

    # Add session middleware for OAuth state management
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        max_age=settings.oauth_state_ttl,
    )

    # Register routers
    register_routers(app)

    # Register base routes
    register_base_routes(app)

    return app


def register_routers(app: FastAPI) -> None:
    """Register API routers"""
    # Auth router
    try:
        app.include_router(
            auth.router,
            prefix=f"{settings.api_v1_prefix}",
            tags=["Authentication"]
        )
        logger.info("✓ Auth router registered")
    except ImportError as e:
        logger.error(f"Could not import auth router: {e}")

    # Categories router
    try:
        app.include_router(
            categories.router,
            prefix=f"{settings.api_v1_prefix}/categories",
            tags=["Categories"]
        )
        logger.info("✓ Categories router registered")
    except ImportError as e:
        logger.error(f"Could not import categories router: {e}")


def register_base_routes(app: FastAPI) -> None:
    """Register base application routes"""

    @app.get("/")
    async def root():
        """Root endpoint with API information"""
        return {
            "message": "Finance Tracker API",
            "version": "0.1.0",
            "status": "running",
            "docs_url": "/docs" if settings.debug else "disabled",
            "features": [
                "OAuth 2.0 Authentication via Keycloak",
                "JWT Token Management",
                "Redis Session Storage",
                "Personal Finance Tracking"
            ]
        }

    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "version": "0.1.0",
            "services": {
                "api": "operational",
                "redis": "operational",
                "keycloak": "operational"
            }
        }

    @app.get("/config")
    async def get_config():
        """
        Get application configuration (development only)

        In production, this endpoint returns 404
        """
        if not settings.debug:
            raise HTTPException(
                status_code=404,
                detail="Endpoint is only available in development mode"
            )

        # Return only safe configuration (no secrets)
        return {
            "project_name": settings.project_name,
            "debug": settings.debug,
            "api_v1_prefix": settings.api_v1_prefix,
            "keycloak_url": settings.keycloak_url,
            "keycloak_realm": settings.keycloak_realm,
            "keycloak_client_id": settings.keycloak_client_id,
            "jwt_algorithm": settings.jwt_algorithm,
            "log_level": settings.log_level,
            "cors_origins": get_cors_origins(),
        }


# Create application instance
app = create_application()


if __name__ == "__main__":
    """
    Development server entry point

    For production use:
    gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
    """
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
