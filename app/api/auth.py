"""
API endpoints for OAuth authorization via Keycloak with Redis session management

Endpoints:
1. GET /auth/login - redirect user to Keycloak for authorization
2. GET /auth/callback - handle callback from Keycloak  
3. GET /auth/me - current user information
4. POST /auth/refresh - refresh access token
5. GET /auth/status - check authentication status
6. POST /auth/logout - logout current session
7. POST /auth/logout-all - logout all user sessions
8. GET /auth/sessions - get user's active sessions

Redis integration:
- OAuth state stored in Redis (CSRF protection)
- Session management and analytics
- Token blacklist for instant logout
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
import httpx
from typing import Dict, Any, List
import secrets
import logging
from datetime import datetime

from app.core.config import settings
from app.core.redis_client import RedisClient, get_redis
from app.auth.dependencies import (
    get_current_user, 
    get_optional_user, 
    revoke_token, 
    revoke_all_user_tokens,
    get_user_sessions
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/login")
async def login(
    request: Request,
    redis: RedisClient = Depends(get_redis),
    redirect_url: str = None
):
    """
    Redirect user to Keycloak for authorization
    
    Steps:
    1. Generate state for CSRF protection
    2. Store state in Redis with metadata
    3. Build authorization URL in Keycloak
    4. Redirect user
    
    Args:
        redirect_url: Optional URL to redirect after successful auth
    """
    try:
        # Generate random state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Store state in Redis with metadata
        state_data = {
            "created_at": datetime.utcnow().isoformat(),
            "ip_address": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown"),
            "redirect_url": redirect_url,
        }
        
        await redis.set_oauth_state(state, state_data)
        logger.info(f"OAuth state created: {state} for IP: {request.client.host}")
        
        # URL for return after authorization
        redirect_uri = str(request.url_for("auth_callback"))
        
        # Build Keycloak authorization URL
        auth_url = (
            f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
            f"/protocol/openid-connect/auth"
            f"?client_id={settings.keycloak_client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&response_type=code"
            f"&scope=openid profile email"
            f"&state={state}"
        )
        
        # Increment login attempts counter
        await redis.increment_counter("login_attempts_total")
        await redis.increment_counter(f"login_attempts_ip:{request.client.host}")
        
        return RedirectResponse(url=auth_url)
        
    except Exception as e:
        logger.error(f"Error in login endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error initiating login"
        )


@router.get("/callback")
async def auth_callback(
    request: Request,
    redis: RedisClient = Depends(get_redis),
    code: str = None,
    state: str = None,
    error: str = None
):
    """
    Handle callback from Keycloak after authorization
    
    Security checks:
    1. Verify no error from Keycloak
    2. Verify authorization code present
    3. Verify state for CSRF protection (from Redis)
    4. Exchange code for tokens
    5. Store refresh token metadata in Redis
    
    Receives:
    - code: authorization code to exchange for tokens
    - state: for CSRF verification
    - error: if authorization failed
    """
    # Check for errors from Keycloak
    if error:
        logger.warning(f"OAuth error from Keycloak: {error}")
        await redis.increment_counter("oauth_errors_total")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authorization error: {error}"
        )
    
    if not code:
        logger.warning("Missing authorization code in callback")
        await redis.increment_counter("oauth_errors_total")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code"
        )
    
    if not state:
        logger.warning("Missing state parameter in callback")
        await redis.increment_counter("oauth_errors_total")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing state parameter"
        )
    
    # Verify state for CSRF protection (get and delete from Redis)
    state_data = await redis.get_oauth_state(state)
    if not state_data:
        logger.warning(f"Invalid or expired OAuth state: {state}")
        await redis.increment_counter("csrf_attempts_total")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state (possible CSRF attack)"
        )
    
    logger.info(f"Valid OAuth state verified: {state}")
    
    try:
        # Exchange authorization code for tokens
        async with httpx.AsyncClient(timeout=30.0) as client:
            token_url = (
                f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
                f"/protocol/openid-connect/token"
            )
            
            redirect_uri = str(request.url_for("auth_callback"))
            
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": settings.keycloak_client_id,
            }
            
            # Add client_secret if available
            if settings.keycloak_client_secret:
                data["client_secret"] = settings.keycloak_client_secret
            
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            
            tokens = response.json()
            
            # Store refresh token metadata in Redis if present
            if "refresh_token" in tokens:
                # Decode refresh token to get JTI and user info
                from jose import jwt
                try:
                    refresh_payload = jwt.get_unverified_claims(tokens["refresh_token"])
                    refresh_jti = refresh_payload.get("jti")
                    user_id = refresh_payload.get("sub")
                    
                    if refresh_jti and user_id:
                        session_data = {
                            "ip_address": request.client.host if request.client else "unknown",
                            "user_agent": request.headers.get("user-agent", "unknown"),
                            "login_method": "oauth",
                            "redirect_url": state_data.get("redirect_url"),
                        }
                        
                        await redis.store_refresh_token(refresh_jti, user_id, session_data)
                        logger.info(f"Refresh token stored for user: {user_id}")
                        
                except Exception as e:
                    logger.warning(f"Could not store refresh token metadata: {e}")
            
            # Increment successful login counter
            await redis.increment_counter("successful_logins_total")
            await redis.increment_counter(f"successful_logins_ip:{request.client.host}")
            
            # Check if we should redirect to a specific URL
            redirect_url = state_data.get("redirect_url")
            if redirect_url:
                logger.info(f"Redirecting to: {redirect_url}")
                # In a real app, you might want to securely pass tokens via secure cookies
                # For now, we'll return them in the response
            
            return {
                "message": "Authorization successful!",
                "access_token": tokens["access_token"],
                "token_type": tokens.get("token_type", "Bearer"),
                "expires_in": tokens.get("expires_in"),
                "refresh_token": tokens.get("refresh_token"),
                "scope": tokens.get("scope"),
                "redirect_url": redirect_url,
            }
            
    except httpx.HTTPStatusError as e:
        error_detail = "Error getting token from Keycloak"
        try:
            error_info = e.response.json()
            error_detail = f"{error_detail}: {error_info.get('error_description', error_info.get('error'))}"
        except:
            pass
            
        logger.error(f"Keycloak token exchange error: {error_detail}")
        await redis.increment_counter("token_exchange_errors_total")
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_detail
        )
    except httpx.RequestError as e:
        logger.error(f"Network error during token exchange: {e}")
        await redis.increment_counter("token_exchange_errors_total")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to connect to Keycloak"
        )
    except Exception as e:
        logger.error(f"Unexpected error in auth callback: {e}")
        await redis.increment_counter("token_exchange_errors_total")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}"
        )


@router.get("/me")
async def get_me(
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis: RedisClient = Depends(get_redis)
):
    """
    Get current authenticated user information
    
    Requires: Bearer token in Authorization header
    """
    try:
        # Increment user info requests counter
        await redis.increment_counter("user_info_requests_total")
        await redis.increment_counter(f"user_info_requests_user:{current_user['user_id']}")
        
        # Return user information (excluding sensitive data)
        return {
            "user_id": current_user["user_id"],
            "username": current_user["username"], 
            "email": current_user["email"],
            "name": current_user["name"],
            "given_name": current_user.get("given_name"),
            "family_name": current_user.get("family_name"),
            "roles": current_user["roles"],
            "groups": current_user["groups"],
            "session_id": current_user.get("session_id"),
            "token_issued_at": datetime.fromtimestamp(current_user["issued_at"]).isoformat() if current_user.get("issued_at") else None,
            "token_expires_at": datetime.fromtimestamp(current_user["expires_at"]).isoformat() if current_user.get("expires_at") else None,
        }
        
    except Exception as e:
        logger.error(f"Error in get_me endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving user information"
        )


@router.post("/refresh")
async def refresh_token_endpoint(
    refresh_token: str,
    redis: RedisClient = Depends(get_redis)
):
    """
    Refresh access token using refresh token
    
    Security:
    1. Check if refresh token is valid in Redis
    2. Exchange with Keycloak for new tokens
    3. Update refresh token metadata
    """
    try:
        # Decode refresh token to get JTI
        from jose import jwt
        try:
            refresh_payload = jwt.get_unverified_claims(refresh_token)
            refresh_jti = refresh_payload.get("jti")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token format"
            )
        
        # Check if refresh token exists in Redis
        if refresh_jti:
            token_data = await redis.get_refresh_token(refresh_jti)
            if not token_data:
                logger.warning(f"Refresh token not found in Redis: {refresh_jti}")
                await redis.increment_counter("invalid_refresh_attempts_total")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token not found or expired"
                )
        
        # Exchange refresh token for new access token
        async with httpx.AsyncClient(timeout=30.0) as client:
            token_url = (
                f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
                f"/protocol/openid-connect/token"
            )
            
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": settings.keycloak_client_id,
            }
            
            if settings.keycloak_client_secret:
                data["client_secret"] = settings.keycloak_client_secret
            
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            
            tokens = response.json()
            
            # Update refresh token usage in Redis
            if refresh_jti:
                await redis.update_refresh_token_usage(refresh_jti)
            
            # Increment successful refresh counter
            await redis.increment_counter("successful_refresh_total")
            
            return {
                "access_token": tokens["access_token"],
                "token_type": tokens.get("token_type", "Bearer"),
                "expires_in": tokens.get("expires_in"),
                "refresh_token": tokens.get("refresh_token", refresh_token),  # May be rotated
                "scope": tokens.get("scope"),
            }
            
    except httpx.HTTPStatusError as e:
        logger.warning("Invalid refresh token attempt")
        await redis.increment_counter("invalid_refresh_attempts_total")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    except httpx.RequestError as e:
        logger.error(f"Network error during token refresh: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to connect to Keycloak"
        )
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error refreshing token: {str(e)}"
        )


@router.get("/status")
async def auth_status(
    current_user: Dict[str, Any] = Depends(get_optional_user),
    redis: RedisClient = Depends(get_redis)
):
    """
    Check authentication status (optional)
    Returns user info if authenticated, otherwise null
    """
    if current_user:
        await redis.increment_counter("auth_status_authenticated_total")
        return {
            "authenticated": True,
            "user": {
                "user_id": current_user["user_id"],
                "username": current_user["username"],
                "email": current_user["email"],
                "roles": current_user["roles"],
                "expires_at": datetime.fromtimestamp(current_user["expires_at"]).isoformat() if current_user.get("expires_at") else None,
            }
        }
    else:
        await redis.increment_counter("auth_status_anonymous_total")
        return {
            "authenticated": False,
            "user": None
        }


@router.post("/logout")
async def logout(
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis: RedisClient = Depends(get_redis)
):
    """
    Logout current session
    
    Actions:
    1. Add current token to blacklist
    2. Revoke refresh token if JTI available
    3. Increment logout counters
    """
    try:
        # Blacklist current access token
        token_jti = current_user.get("token_jti")
        expires_at = datetime.fromtimestamp(current_user["expires_at"])
        
        if token_jti:
            await revoke_token(token_jti, expires_at, redis)
            logger.info(f"Access token blacklisted for user: {current_user['username']}")
        
        # Note: We can't easily revoke refresh token here since we don't have it
        # In a real implementation, you might store the refresh token JTI 
        # when creating the access token
        
        # Increment logout counter
        await redis.increment_counter("logout_total")
        await redis.increment_counter(f"logout_user:{current_user['user_id']}")
        
        return {
            "message": "Logged out successfully",
            "user": current_user["username"]
        }
        
    except Exception as e:
        logger.error(f"Error in logout endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error during logout"
        )


@router.post("/logout-all")
async def logout_all(
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis: RedisClient = Depends(get_redis)
):
    """
    Logout all sessions for current user
    
    Actions:
    1. Revoke all refresh tokens for user
    2. Blacklist current access token
    3. Return count of revoked sessions
    """
    try:
        # Revoke all refresh tokens for user
        revoked_count = await revoke_all_user_tokens(current_user["user_id"], redis)
        
        # Blacklist current access token
        token_jti = current_user.get("token_jti")
        if token_jti:
            expires_at = datetime.fromtimestamp(current_user["expires_at"])
            await revoke_token(token_jti, expires_at, redis)
        
        # Increment logout all counter
        await redis.increment_counter("logout_all_total")
        await redis.increment_counter(f"logout_all_user:{current_user['user_id']}")
        
        logger.info(f"User {current_user['username']} logged out from {revoked_count} sessions")
        
        return {
            "message": f"Logged out from {revoked_count} sessions",
            "user": current_user["username"],
            "sessions_revoked": revoked_count
        }
        
    except Exception as e:
        logger.error(f"Error in logout-all endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error during global logout"
        )


@router.get("/sessions")
async def get_active_sessions(
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis: RedisClient = Depends(get_redis)
):
    """
    Get all active sessions for current user
    
    Returns list of active refresh tokens with metadata
    """
    try:
        sessions = await get_user_sessions(current_user["user_id"], redis)
        
        # Format sessions for response
        formatted_sessions = []
        for session in sessions:
            formatted_sessions.append({
                "created_at": session.get("created_at"),
                "last_used": session.get("last_used"),
                "ip_address": session.get("ip_address"),
                "user_agent": session.get("user_agent"),
                "login_method": session.get("login_method"),
                "expires_in_seconds": session.get("expires_in_seconds"),
            })
        
        return {
            "user": current_user["username"],
            "total_sessions": len(formatted_sessions),
            "sessions": formatted_sessions
        }
        
    except Exception as e:
        logger.error(f"Error getting user sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving sessions"
        )


@router.get("/config")
async def get_auth_config():
    """
    Get OAuth configuration for frontend
    
    Returns URLs and settings needed by frontend applications
    """
    return {
        "keycloak_url": settings.keycloak_url,
        "realm": settings.keycloak_realm,
        "client_id": settings.keycloak_client_id,
        "endpoints": {
            "login": "/api/v1/auth/login",
            "callback": "/api/v1/auth/callback", 
            "me": "/api/v1/auth/me",
            "refresh": "/api/v1/auth/refresh",
            "status": "/api/v1/auth/status",
            "logout": "/api/v1/auth/logout",
            "logout_all": "/api/v1/auth/logout-all",
            "sessions": "/api/v1/auth/sessions",
        },
        "keycloak_endpoints": {
            "authorization": f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/auth",
            "token": f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/token",
            "userinfo": f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/userinfo",
            "logout": f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/logout",
        }
    }


@router.get("/analytics")
async def get_auth_analytics(
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis: RedisClient = Depends(get_redis)
):
    """
    Get authentication analytics
    
    Requires: Admin role
    """
    # Check if user has admin role
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    
    try:
        # Get Redis statistics
        redis_stats = await redis.get_stats()
        
        # Get authentication counters
        analytics = {
            "redis_stats": redis_stats,
            "auth_metrics": {
                "login_attempts": await redis.get_cache("login_attempts_total") or "0",
                "successful_logins": await redis.get_cache("successful_logins_total") or "0",
                "oauth_errors": await redis.get_cache("oauth_errors_total") or "0",
                "csrf_attempts": await redis.get_cache("csrf_attempts_total") or "0",
                "logout_total": await redis.get_cache("logout_total") or "0",
                "logout_all_total": await redis.get_cache("logout_all_total") or "0",
                "refresh_attempts": await redis.get_cache("successful_refresh_total") or "0",
                "invalid_refresh_attempts": await redis.get_cache("invalid_refresh_attempts_total") or "0",
            }
        }
        
        return analytics
        
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving analytics"
        )