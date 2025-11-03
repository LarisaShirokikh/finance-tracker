"""
Finance Tracker Application Configuration

Uses Pydantic Settings for automatic validation
and loading environment variables from .env file.

Principles:
1. All settings in one place
2. Automatic type validation
3. Environment variables override defaults
4. Different settings for dev/test/prod
"""

from typing import List, Optional
from pydantic import Field, field_validator, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings with automatic loading from environment variables
    
    Pydantic Settings automatically:
    - Reads .env file
    - Converts data types
    - Validates values
    - Overrides with environment variables
    """
    
    # === MAIN SETTINGS ===
    project_name: str = Field(default="Finance Tracker", description="Project name")
    debug: bool = Field(default=False, description="Debug mode")
    api_v1_prefix: str = Field(default="/api/v1", description="API v1 prefix")
    
    # === DATABASE ===
    database_url: str = Field(
        default="postgresql://finance_user:finance_password@localhost:5432/finance_db",
        description="PostgreSQL connection URL"
    )
    
    # === KEYCLOAK SETTINGS ===
    keycloak_url: str = Field(
        default="http://localhost:8080", 
        description="Keycloak server URL"
    )
    keycloak_realm: str = Field(
        default="finance-realm",
        description="Keycloak realm for our application"
    )
    keycloak_client_id: str = Field(
        default="finance-client",
        description="Keycloak client ID"
    )
    keycloak_client_secret: Optional[str] = Field(
        default=None,
        description="Client secret (optional for public clients)"
    )
    
    # === JWT SETTINGS ===
    jwt_algorithm: str = Field(
        default="RS256",
        description="JWT algorithm (RS256 for Keycloak)"
    )
    access_token_expire_minutes: int = Field(
        default=30,
        description="Access token lifetime in minutes"
    )
    refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token lifetime in days"
    )

    # === REDIS CONFIGURATION ===
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        env="REDIS_URL",
        description="Redis connection URL for caching and sessions"
    )
    redis_password: str = Field(
        default="",
        env="REDIS_PASSWORD", 
        description="Redis password"
    )
    redis_db: int = Field(
        default=0,
        env="REDIS_DB",
        description="Redis database number (0-15)"
    )
    redis_max_connections: int = Field(
        default=20,
        env="REDIS_MAX_CONNECTIONS",
        description="Maximum Redis connections in pool"
    )
    
    # Cache timeouts (in seconds)
    oauth_state_ttl: int = Field(
        default=600,  # 10 minutes
        env="OAUTH_STATE_TTL",
        description="OAuth state expiration time in seconds"
    )
    keycloak_jwks_cache_ttl: int = Field(
        default=3600,  # 1 hour
        env="KEYCLOAK_JWKS_CACHE_TTL", 
        description="Keycloak JWKS cache time in seconds"
    )
    refresh_token_ttl: int = Field(
        default=2592000,  # 30 days
        env="REFRESH_TOKEN_TTL",
        description="Refresh token TTL in seconds"
    )
    token_blacklist_ttl: int = Field(
        default=86400,  # 24 hours
        env="TOKEN_BLACKLIST_TTL",
        description="How long to keep blacklisted tokens in Redis"
    )
    
    # === SECURITY ===
    secret_key: str = Field(
        default="change-this-secret-key-in-production",
        description="Secret key for session signing"
    )
    
    # === CORS ===
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed origins for CORS"
    )
    
    # === LOGGING ===
    log_level: str = Field(
        default="INFO",
        description="Logging level"
    )
    
    @field_validator("database_url")
    def validate_database_url(cls, v):
        """Validate that database URL is correct"""
        if not v.startswith("postgresql://"):
            raise ValueError("Database URL must start with postgresql://")
        return v
    
    @field_validator("keycloak_url")
    def validate_keycloak_url(cls, v):
        """Validate that Keycloak URL is correct"""
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Keycloak URL must start with http:// or https://")
        return v
    
    @field_validator("log_level")
    def validate_log_level(cls, v):
        """Validate logging level"""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of: {allowed_levels}")
        return v.upper()

    @field_validator("redis_url")
    def validate_redis_url(cls, v):
        """Validate Redis URL format"""
        if not v.startswith("redis://"):
            raise ValueError("Redis URL must start with redis://")
        return v

    class Config:
        # Read environment variables from .env file
        env_file = ".env"
        env_file_encoding = "utf-8"
            
        # Environment variables override default values
        case_sensitive = False


# Create a global instance of settings
# It will be automatically loaded when the module is imported
settings = Settings()


def get_database_url() -> str:
    """Get the database URL"""
    return settings.database_url

def get_redis_url() -> str:
    """Get Redis connection URL"""
    return settings.redis_url

def get_keycloak_config() -> dict:
    """Get Keycloak configuration"""
    return {
        "url": settings.keycloak_url,
        "realm": settings.keycloak_realm,
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
    }


def is_development() -> bool:
    """Check if we are in development mode"""
    return settings.debug


def get_cors_origins() -> List[str]:
    """Get allowed origins for CORS"""
    return settings.allowed_origins