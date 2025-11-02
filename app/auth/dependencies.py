"""
FastAPI dependencies for OAuth authorization via Keycloak

Core functions:
1. get_current_user - validates JWT token and returns user data
2. require_roles - checks user roles (RBAC)
3. get_optional_user - optional authorization
"""

from typing import Optional, List, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from jose import jwt, JWTError

from app.core.config import settings


# Security scheme for Bearer tokens
security = HTTPBearer()


class KeycloakJWTBearer:
    """Class for validating JWT tokens from Keycloak"""
    
    def __init__(self):
        self.keycloak_url = settings.keycloak_url
        self.realm = settings.keycloak_realm
        self.client_id = settings.keycloak_client_id
        # Cache for public key
        self._public_key_cache: Optional[str] = None

    async def get_public_key(self) -> str:
        """Get public key for JWT validation"""
        if self._public_key_cache:
            return self._public_key_cache
            
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Get JWKS (JSON Web Key Set)
                jwks_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/certs"
                response = await client.get(jwks_url)
                response.raise_for_status()
                jwks = response.json()
                
                if not jwks.get("keys"):
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Unable to get keys from Keycloak"
                    )
                
                # Take first key (in production search by kid)
                key_data = jwks["keys"][0]
                
                # Convert to PEM format (simplified version)
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
                
                self._public_key_cache = pem_key
                return pem_key
                
        except Exception as e:
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
        """Verify and decode JWT token"""
        try:
            # Get public key
            public_key = await self.get_public_key()
            
            # Verify and decode token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[settings.jwt_algorithm],
                audience=self.client_id,
                issuer=f"{self.keycloak_url}/realms/{self.realm}"
            )
            
            return payload
            
        except JWTError as e:
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
        
        return {
            "user_id": payload.get("sub"),
            "username": payload.get("preferred_username"),
            "email": payload.get("email"),
            "name": payload.get("name"),
            "roles": list(set(roles)),  # remove duplicates
            "groups": payload.get("groups", []),
            "session_id": payload.get("sid"),
            "expires_at": payload.get("exp"),
        }


# Global instance for use in dependencies
jwt_bearer = KeycloakJWTBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
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
    
    return await jwt_bearer.get_user_info(credentials.credentials)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """
    Optional authorization - returns user if token exists,
    otherwise None
    """
    if not credentials:
        return None
    
    try:
        return await jwt_bearer.get_user_info(credentials.credentials)
    except HTTPException:
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
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {', '.join(required_roles)}. "
                       f"User has: {', '.join(user_roles)}"
            )
        
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
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required all roles: {', '.join(required_roles)}. "
                       f"Missing: {', '.join(missing_roles)}"
            )
        
        return user
    
    return check_all_roles