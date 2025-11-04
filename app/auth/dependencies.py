"""
FastAPI dependencies for OAuth authorization via Keycloak

Core functions:
1. get_current_user - validates JWT token and returns user data
2. require_roles - checks user roles (RBAC)
3. get_optional_user - optional authorization

Redis integration:
- JWKS caching for performance
- Token blacklist for instant logout
- Improved error handling and logging
"""

import base64
import datetime
import logging
from typing import Optional, List, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from jose import jwt, JWTError

from app.core.config import settings
from app.core.redis_client import RedisClient, get_redis

logger = logging.getLogger(__name__)


# Security scheme for Bearer tokens
security = HTTPBearer()


class KeycloakJWTBearer:
    """Class for validating JWT tokens from Keycloak
    Features:
    - JWKS caching in Redis (performance boost)
    - Token blacklist checking (instant logout)
    - Proper error handling and logging
    - Async operations
    """
    
    def __init__(self, redis_client: RedisClient):
        self.keycloak_url = settings.keycloak_url
        self.realm = settings.keycloak_realm
        self.client_id = settings.keycloak_client_id
        self.redis = redis_client  # Redis dependency injection

    async def get_public_key(self) -> str:
        """
        Get public key for JWT validation with Redis caching
        
        Flow:
        1. Check Redis cache first
        2. If not cached, fetch from Keycloak  
        3. Cache in Redis for future use
        4. Return PEM formatted key
        """
        try:
            # Try to get from Redis cache first
            jwks = await self.redis.get_keycloak_jwks()
            
            if not jwks:
                logger.debug("JWKS not in cache, fetching from Keycloak")
                # Fetch from Keycloak if not cached
                async with httpx.AsyncClient(timeout=10.0) as client:
                    jwks_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/certs"
                    response = await client.get(jwks_url)
                    response.raise_for_status()
                    jwks = response.json()
                    
                    if not jwks.get("keys"):
                        raise HTTPException(
                            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Unable to get keys from Keycloak"
                        )
                    
                    # Cache JWKS in Redis
                    await self.redis.set_keycloak_jwks(jwks)
                    logger.debug("JWKS fetched and cached")
            else:
                logger.debug("JWKS retrieved from Redis cache")
            
            # Convert first key to PEM format
            key_data = jwks["keys"][0]
            
            # Import crypto libraries inside function
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import base64
            
            # Decode RSA key parameters
            n = int.from_bytes(self._base64url_decode(key_data["n"]), "big")
            e = int.from_bytes(self._base64url_decode(key_data["e"]), "big")
            
            # Create public key
            public_numbers = rsa.RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key()
            
            # Convert to PEM
            pem_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            return pem_key
                
        except httpx.RequestError as e:
            logger.error(f"Network error fetching JWKS: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to connect to Keycloak"
            )
        except Exception as e:
            logger.error(f"Error getting public key: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Error getting public key: {str(e)}"
            )

    def _base64url_decode(self, data: str) -> bytes:
        """Base64url decoding"""
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    async def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token
        Security checks:
        1. JWT signature validation
        2. Audience verification  
        3. Issuer verification
        4. Expiration check
        5. Blacklist check (for instant logout)
        """
        try:
            # First decode without verification to get JTI
            unverified_payload = jwt.get_unverified_claims(token)
            token_jti = unverified_payload.get("jti")
            
            # Check if token is blacklisted (instant logout)
            if token_jti and await self.redis.is_token_blacklisted(token_jti):
                logger.warning(f"Blacklisted token attempted: {token_jti}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Get public key for verification
            public_key = await self.get_public_key()
            
            # Verify and decode token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[settings.jwt_algorithm],
                audience=self.client_id,
                issuer=f"{self.keycloak_url}/realms/{self.realm}",
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_iat": True,
                }
            )
            
            logger.debug(f"Token verified successfully for user: {payload.get('sub')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token attempted")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidAudienceError:
            logger.warning("Invalid audience in token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token audience",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidIssuerError:
            logger.warning("Invalid issuer in token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token issuer",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except JWTError as e:
            logger.warning(f"JWT validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )


    async def get_user_info(self, token: str) -> Dict[str, Any]:
        """Extract user information from token"""
        payload = await self.verify_token(token)
        
        # Extract roles
        roles = []
        if "realm_access" in payload:
            roles.extend(payload["realm_access"].get("roles", []))
        if "resource_access" in payload and self.client_id in payload["resource_access"]:
            roles.extend(payload["resource_access"][self.client_id].get("roles", []))
        
        user_info = {
            "user_id": payload.get("sub"),
            "username": payload.get("preferred_username"),
            "email": payload.get("email"),
            "name": payload.get("name"),
            "given_name": payload.get("given_name"),
            "family_name": payload.get("family_name"),
            "roles": list(set(roles)),  # remove duplicates
            "groups": payload.get("groups", []),
            "session_id": payload.get("sid"),
            "token_jti": payload.get("jti"),
            "expires_at": payload.get("exp"),
            "issued_at": payload.get("iat"),
        }
        
        logger.debug(f"User info extracted for: {user_info['username']}")
        return user_info


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    redis: RedisClient = Depends(get_redis)
) -> Dict[str, Any]:
    """
    FastAPI dependency to get current user
    
    Usage:
    @app.get("/protected")
    async def protected_endpoint(user: dict = Depends(get_current_user)):
        return {"message": f"Hello, {user['username']}!"}
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create JWT bearer instance with Redis
    jwt_bearer = KeycloakJWTBearer(redis)
    
    try:
        user_info = await jwt_bearer.get_user_info(credentials.credentials)
        
        # Increment login counter for analytics
        await redis.increment_counter(f"user_requests:{user_info['user_id']}")
        
        return user_info
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Unexpected error in get_current_user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal authentication error"
        )


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    redis: RedisClient = Depends(get_redis)
) -> Optional[Dict[str, Any]]:
    """
    Optional authorization - returns user if token exists,
    otherwise None
    """
    if not credentials:
        return None
    
    try:
        jwt_bearer = KeycloakJWTBearer(redis)
        return await jwt_bearer.get_user_info(credentials.credentials)
    except HTTPException:
        # Authentication failed, but this is optional
        logger.debug("Optional authentication failed")
        return None
    except Exception as e:
        logger.warning(f"Error in optional authentication: {e}")
        return None


def require_roles(required_roles: List[str]):
    """
    Dependency factory for role checking (RBAC)
    
    Usage:
    @app.get("/admin")
    async def admin_endpoint(user: dict = Depends(require_roles(["admin"]))):
        return {"message": "Admin only"}
    """
    async def check_roles(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_roles = user.get("roles", [])
        
        # Check if user has at least one of required roles
        if not any(role in user_roles for role in required_roles):
            logger.warning(
                f"Access denied for user {user['username']}. "
                f"Required: {required_roles}, User has: {user_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {', '.join(required_roles)}. "
                       f"User has: {', '.join(user_roles)}"
            )
        
        logger.debug(f"Role check passed for user {user['username']}")
        return user
    
    return check_roles


def require_all_roles(required_roles: List[str]):
    """
    Dependency factory to check ALL roles
    User must have ALL specified roles
    """
    async def check_all_roles(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_roles = user.get("roles", [])
        
        missing_roles = [role for role in required_roles if role not in user_roles]
        if missing_roles:
            logger.warning(
                f"Access denied for user {user['username']}. "
                f"Missing roles: {missing_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required all roles: {', '.join(required_roles)}. "
                       f"Missing: {', '.join(missing_roles)}"
            )
        
        logger.debug(f"All roles check passed for user {user['username']}")
        return user
    
    return check_all_roles

async def revoke_token(
    token_jti: str,
    expires_at: datetime,
    redis: RedisClient = Depends(get_redis)
) -> None:
    """
    Revoke a specific token (add to blacklist)
    
    Args:
        token_jti: JWT ID to revoke
        expires_at: When token expires naturally
        redis: Redis client
    """
    await redis.blacklist_token(token_jti, expires_at)
    logger.info(f"Token revoked: {token_jti}")


async def revoke_all_user_tokens(
    user_id: str,
    redis: RedisClient = Depends(get_redis)
) -> int:
    """
    Revoke all tokens for a user (global logout)
    
    Args:
        user_id: User ID to revoke all tokens for
        redis: Redis client
        
    Returns:
        Number of tokens revoked
    """
    count = await redis.revoke_all_user_tokens(user_id)
    logger.info(f"Revoked {count} tokens for user: {user_id}")
    return count


async def get_user_sessions(
    user_id: str,
    redis: RedisClient = Depends(get_redis)
) -> List[Dict[str, Any]]:
    """
    Get all active sessions for a user
    
    Args:
        user_id: User ID
        redis: Redis client
        
    Returns:
        List of active sessions
    """
    sessions = await redis.get_user_sessions(user_id)
    logger.debug(f"Retrieved {len(sessions)} sessions for user: {user_id}")
    return sessions








