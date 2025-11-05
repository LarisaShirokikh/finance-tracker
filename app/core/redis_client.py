"""
Redis client for caching and session management

Features:
1. OAuth state storage (CSRF protection)
2. Keycloak JWKS caching (performance)
3. Token blacklist (instant logout)
4. Refresh token storage (session control)
5. User session management
"""

import json
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging

import redis.asyncio as redis
from redis.asyncio import Redis

from app.core.config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    """
    Redis client wrapper with helper methods for authentication and caching
    
    Usage:
        redis_client = RedisClient()
        await redis_client.connect()
        await redis_client.set_oauth_state("state123", {"user_data": "value"})
    """
    
    def __init__(self):
        self.redis: Optional[Redis] = None
        self._connection_pool = None
        
    async def connect(self) -> None:
        """Initialize Redis connection pool"""
        try:
            # Parse Redis URL for connection
            redis_url = settings.redis_url
            
            # Create connection pool
            self.redis = await redis.from_url(
                redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=settings.redis_max_connections,
                retry_on_timeout=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            
            # Test connection
            await self.redis.ping()
            logger.info("✅ Redis connected successfully")
            
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
            logger.info("Redis connection closed")
    
    async def health_check(self) -> bool:
        """Check if Redis is healthy"""
        try:
            if not self.redis:
                return False
            await self.redis.ping()
            return True
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False

    # === OAUTH STATE MANAGEMENT ===
    
    async def set_oauth_state(self, state: str, data: Dict[str, Any]) -> None:
        """
        Store OAuth state for CSRF protection
        
        Args:
            state: Random CSRF token
            data: Additional data (user_id, redirect_url, etc.)
        """
        key = f"oauth_state:{state}"
        value = json.dumps(data)
        
        await self.redis.setex(
            key, 
            settings.oauth_state_ttl,  # 10 minutes
            value
        )
        logger.debug(f"OAuth state stored: {state}")
    
    async def get_oauth_state(self, state: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve and delete OAuth state (one-time use)
        
        Args:
            state: CSRF token to verify
            
        Returns:
            Stored data or None if not found/expired
        """
        key = f"oauth_state:{state}"
        
        # Get and delete in one operation (atomic)
        pipeline = self.redis.pipeline()
        pipeline.get(key)
        pipeline.delete(key)
        results = await pipeline.execute()
        
        data = results[0]
        if data:
            logger.debug(f"OAuth state retrieved and deleted: {state}")
            return json.loads(data)
        else:
            logger.warning(f"OAuth state not found or expired: {state}")
            return None

    # === KEYCLOAK JWKS CACHING ===
    
    async def set_keycloak_jwks(self, jwks: Dict[str, Any]) -> None:
        """
        Cache Keycloak JWKS (JSON Web Key Set)
        
        Args:
            jwks: Public keys from Keycloak
        """
        key = "keycloak:jwks"
        value = json.dumps(jwks)
        
        await self.redis.setex(
            key,
            settings.keycloak_jwks_cache_ttl,  # 1 hour
            value
        )
        logger.debug("Keycloak JWKS cached")
    
    async def get_keycloak_jwks(self) -> Optional[Dict[str, Any]]:
        """
        Get cached Keycloak JWKS
        
        Returns:
            Cached JWKS or None if not found/expired
        """
        key = "keycloak:jwks"
        data = await self.redis.get(key)
        
        if data:
            logger.debug("Keycloak JWKS retrieved from cache")
            return json.loads(data)
        else:
            logger.debug("Keycloak JWKS not in cache")
            return None

    # === TOKEN BLACKLIST ===
    
    async def blacklist_token(self, token_jti: str, expires_at: datetime) -> None:
        """
        Add token to blacklist (for instant logout)
        
        Args:
            token_jti: JWT ID (unique token identifier)
            expires_at: When token naturally expires
        """
        key = f"blacklist:{token_jti}"
        
        # Calculate TTL - keep in blacklist until token expires
        now = datetime.utcnow()
        if expires_at > now:
            ttl = int((expires_at - now).total_seconds())
        else:
            ttl = settings.token_blacklist_ttl  # Default 24 hours
        
        await self.redis.setex(key, ttl, "blacklisted")
        logger.debug(f"Token blacklisted: {token_jti}")
    
    async def is_token_blacklisted(self, token_jti: str) -> bool:
        """
        Check if token is blacklisted
        
        Args:
            token_jti: JWT ID to check
            
        Returns:
            True if token is blacklisted
        """
        key = f"blacklist:{token_jti}"
        exists = await self.redis.exists(key)
        
        if exists:
            logger.debug(f"Token is blacklisted: {token_jti}")
            return True
        else:
            return False

    # === REFRESH TOKEN MANAGEMENT ===
    
    async def store_refresh_token(
        self, 
        token_jti: str, 
        user_id: str, 
        session_data: Dict[str, Any]
    ) -> None:
        """
        Store refresh token metadata
        
        Args:
            token_jti: Refresh token JTI
            user_id: User ID
            session_data: Additional session info
        """
        key = f"refresh_token:{token_jti}"
        value = json.dumps({
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "last_used": datetime.utcnow().isoformat(),
            **session_data
        })
        
        await self.redis.setex(
            key,
            settings.refresh_token_ttl,  # 30 days
            value
        )
        logger.debug(f"Refresh token stored: {token_jti}")
    
    async def get_refresh_token(self, token_jti: str) -> Optional[Dict[str, Any]]:
        """
        Get refresh token metadata
        
        Args:
            token_jti: Refresh token JTI
            
        Returns:
            Token metadata or None if not found
        """
        key = f"refresh_token:{token_jti}"
        data = await self.redis.get(key)
        
        if data:
            logger.debug(f"Refresh token found: {token_jti}")
            return json.loads(data)
        else:
            logger.debug(f"Refresh token not found: {token_jti}")
            return None
    
    async def update_refresh_token_usage(self, token_jti: str) -> None:
        """
        Update last_used timestamp for refresh token
        
        Args:
            token_jti: Refresh token JTI
        """
        key = f"refresh_token:{token_jti}"
        data = await self.redis.get(key)
        
        if data:
            token_data = json.loads(data)
            token_data["last_used"] = datetime.utcnow().isoformat()
            
            # Get remaining TTL and preserve it
            ttl = await self.redis.ttl(key)
            if ttl > 0:
                await self.redis.setex(key, ttl, json.dumps(token_data))
                logger.debug(f"Refresh token usage updated: {token_jti}")
    
    async def revoke_refresh_token(self, token_jti: str) -> None:
        """
        Revoke refresh token (delete from storage)
        
        Args:
            token_jti: Refresh token JTI to revoke
        """
        key = f"refresh_token:{token_jti}"
        deleted = await self.redis.delete(key)
        
        if deleted:
            logger.debug(f"Refresh token revoked: {token_jti}")
        else:
            logger.debug(f"Refresh token not found for revocation: {token_jti}")
    
    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all refresh tokens for a user (global logout)
        
        Args:
            user_id: User ID
            
        Returns:
            Number of tokens revoked
        """
        pattern = "refresh_token:*"
        revoked_count = 0
        
        # Scan for all refresh tokens
        async for key in self.redis.scan_iter(pattern):
            data = await self.redis.get(key)
            if data:
                token_data = json.loads(data)
                if token_data.get("user_id") == user_id:
                    await self.redis.delete(key)
                    revoked_count += 1
        
        logger.info(f"Revoked {revoked_count} refresh tokens for user: {user_id}")
        return revoked_count

    # === USER SESSION MANAGEMENT ===
    
    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of active sessions
        """
        pattern = "refresh_token:*"
        sessions = []
        
        async for key in self.redis.scan_iter(pattern):
            data = await self.redis.get(key)
            if data:
                token_data = json.loads(data)
                if token_data.get("user_id") == user_id:
                    # Get TTL for session
                    ttl = await self.redis.ttl(key)
                    token_data["expires_in_seconds"] = ttl
                    sessions.append(token_data)
        
        return sessions

    # === GENERAL CACHING ===
    
    async def set_cache(
        self, 
        key: str, 
        value: Any, 
        ttl: int = 3600
    ) -> None:
        """
        Generic cache setter
        
        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl: Time to live in seconds
        """
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        elif not isinstance(value, str):
            value = str(value)
            
        await self.redis.setex(key, ttl, value)
    
    async def get_cache(self, key: str) -> Optional[str]:
        """
        Generic cache getter
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None
        """
        return await self.redis.get(key)
    
    async def delete_cache(self, key: str) -> bool:
        """
        Delete cache key
        
        Args:
            key: Cache key to delete
            
        Returns:
            True if key was deleted
        """
        deleted = await self.redis.delete(key)
        return bool(deleted)

    # === ANALYTICS & MONITORING ===
    
    async def increment_counter(self, key: str, ttl: int = 86400) -> int:
        """
        Increment counter with TTL
        
        Args:
            key: Counter key
            ttl: Time to live in seconds
            
        Returns:
            New counter value
        """
        pipeline = self.redis.pipeline()
        pipeline.incr(key)
        pipeline.expire(key, ttl)
        results = await pipeline.execute()
        return results[0]
    
    async def get_stats(self) -> Dict[str, Any]:
        """
        Get Redis statistics
        
        Returns:
            Redis info and custom stats
        """
        info = await self.redis.info()
        
        # Count our keys
        oauth_states = len([key async for key in self.redis.scan_iter("oauth_state:*")])
        refresh_tokens = len([key async for key in self.redis.scan_iter("refresh_token:*")])
        blacklisted = len([key async for key in self.redis.scan_iter("blacklist:*")])
        
        return {
            "redis_version": info.get("redis_version"),
            "connected_clients": info.get("connected_clients"),
            "used_memory_human": info.get("used_memory_human"),
            "total_commands_processed": info.get("total_commands_processed"),
            "oauth_states": oauth_states,
            "refresh_tokens": refresh_tokens,
            "blacklisted_tokens": blacklisted,
            "jwks_cached": await self.redis.exists("keycloak:jwks"),
        }


# Global Redis client instance
redis_client = RedisClient()


async def get_redis() -> RedisClient:
    """
    Dependency function for FastAPI
    
    Usage:
        @app.get("/endpoint")
        async def endpoint(redis: RedisClient = Depends(get_redis)):
            await redis.set_cache("key", "value")
    """
    if not redis_client.redis:
        await redis_client.connect()
    return redis_client


async def init_redis() -> None:
    """Initialize Redis connection on app startup"""
    await redis_client.connect()


async def close_redis() -> None:
    """Close Redis connection on app shutdown"""
    await redis_client.disconnect()