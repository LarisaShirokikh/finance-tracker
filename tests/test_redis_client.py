"""
Unit tests for Redis client functionality

Tests:
1. Connection and health checks
2. OAuth state management (CSRF protection)
3. JWKS caching for performance
4. Token blacklist for instant logout  
5. Refresh token session management
6. General caching and counters
7. Analytics and monitoring
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock
import json

from app.core.redis_client import RedisClient


@pytest.mark.unit
class TestRedisClientConnection:
    """Test Redis connection and basic operations"""
    
    async def test_connect_success(self, mock_redis):
        """Test successful Redis connection"""
        await mock_redis.connect()
        assert mock_redis.connected is True
        
    async def test_disconnect(self, connected_mock_redis):
        """Test Redis disconnection"""
        assert connected_mock_redis.connected is True
        await connected_mock_redis.disconnect()
        assert connected_mock_redis.connected is False
        
    async def test_health_check_connected(self, connected_mock_redis):
        """Test health check when connected"""
        health = await connected_mock_redis.health_check()
        assert health is True
        
    async def test_health_check_disconnected(self, mock_redis):
        """Test health check when disconnected"""
        health = await mock_redis.health_check()
        assert health is False


@pytest.mark.unit
class TestOAuthStateManagement:
    """Test OAuth state management for CSRF protection"""
    
    async def test_set_oauth_state(self, connected_mock_redis):
        """Test storing OAuth state"""
        state = "test_state_123"
        data = {
            "user_id": "user_123",
            "redirect_url": "http://example.com",
            "ip_address": "127.0.0.1"
        }
        
        await connected_mock_redis.set_oauth_state(state, data)
        
        # Verify state was stored
        key = f"oauth_state:{state}"
        assert key in connected_mock_redis.data
        stored_data = json.loads(connected_mock_redis.data[key]["data"])
        assert stored_data == data
        
    async def test_get_oauth_state_valid(self, connected_mock_redis):
        """Test retrieving valid OAuth state"""
        state = "test_state_123"
        data = {"user_id": "user_123"}
        
        await connected_mock_redis.set_oauth_state(state, data)
        retrieved_data = await connected_mock_redis.get_oauth_state(state)
        
        assert retrieved_data == data
        
        # Verify state was deleted (one-time use)
        key = f"oauth_state:{state}"
        assert key not in connected_mock_redis.data
        
    async def test_get_oauth_state_not_found(self, connected_mock_redis):
        """Test retrieving non-existent OAuth state"""
        retrieved_data = await connected_mock_redis.get_oauth_state("nonexistent")
        assert retrieved_data is None
        
    async def test_get_oauth_state_expired(self, connected_mock_redis):
        """Test retrieving expired OAuth state"""
        state = "expired_state"
        data = {"user_id": "user_123"}
        
        # Manually set expired state
        key = f"oauth_state:{state}"
        connected_mock_redis.data[key] = {
            "data": json.dumps(data),
            "expires_at": datetime.utcnow() - timedelta(minutes=1)  # Expired
        }
        
        retrieved_data = await connected_mock_redis.get_oauth_state(state)
        assert retrieved_data is None


@pytest.mark.unit
class TestJWKSCaching:
    """Test Keycloak JWKS caching for performance"""
    
    async def test_set_keycloak_jwks(self, connected_mock_redis):
        """Test storing JWKS in cache"""
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key",
                    "n": "test_modulus",
                    "e": "AQAB"
                }
            ]
        }
        
        await connected_mock_redis.set_keycloak_jwks(jwks)
        
        # Verify JWKS was cached
        assert "keycloak:jwks" in connected_mock_redis.data
        stored_jwks = json.loads(connected_mock_redis.data["keycloak:jwks"]["data"])
        assert stored_jwks == jwks
        
    async def test_get_keycloak_jwks_cached(self, connected_mock_redis):
        """Test retrieving cached JWKS"""
        jwks = {"keys": [{"kty": "RSA"}]}
        
        await connected_mock_redis.set_keycloak_jwks(jwks)
        retrieved_jwks = await connected_mock_redis.get_keycloak_jwks()
        
        assert retrieved_jwks == jwks
        
    async def test_get_keycloak_jwks_not_cached(self, connected_mock_redis):
        """Test retrieving JWKS when not cached"""
        retrieved_jwks = await connected_mock_redis.get_keycloak_jwks()
        assert retrieved_jwks is None
        
    async def test_get_keycloak_jwks_expired(self, connected_mock_redis):
        """Test retrieving expired JWKS"""
        jwks = {"keys": [{"kty": "RSA"}]}
        
        # Manually set expired JWKS
        connected_mock_redis.data["keycloak:jwks"] = {
            "data": json.dumps(jwks),
            "expires_at": datetime.utcnow() - timedelta(minutes=1)  # Expired
        }
        
        retrieved_jwks = await connected_mock_redis.get_keycloak_jwks()
        assert retrieved_jwks is None
        assert "keycloak:jwks" not in connected_mock_redis.data  # Should be cleaned up


@pytest.mark.unit
class TestTokenBlacklist:
    """Test token blacklist for instant logout"""
    
    async def test_blacklist_token(self, connected_mock_redis):
        """Test adding token to blacklist"""
        token_jti = "token_123"
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        await connected_mock_redis.blacklist_token(token_jti, expires_at)
        
        # Verify token was blacklisted
        key = f"blacklist:{token_jti}"
        assert key in connected_mock_redis.data
        assert connected_mock_redis.data[key]["expires_at"] == expires_at
        
    async def test_is_token_blacklisted_true(self, connected_mock_redis):
        """Test checking blacklisted token"""
        token_jti = "token_123"
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        await connected_mock_redis.blacklist_token(token_jti, expires_at)
        is_blacklisted = await connected_mock_redis.is_token_blacklisted(token_jti)
        
        assert is_blacklisted is True
        
    async def test_is_token_blacklisted_false(self, connected_mock_redis):
        """Test checking non-blacklisted token"""
        is_blacklisted = await connected_mock_redis.is_token_blacklisted("nonexistent")
        assert is_blacklisted is False
        
    async def test_is_token_blacklisted_expired(self, connected_mock_redis):
        """Test checking expired blacklisted token"""
        token_jti = "expired_token"
        
        # Manually set expired blacklist entry
        key = f"blacklist:{token_jti}"
        connected_mock_redis.data[key] = {
            "blacklisted_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "expires_at": datetime.utcnow() - timedelta(hours=1)  # Expired
        }
        
        is_blacklisted = await connected_mock_redis.is_token_blacklisted(token_jti)
        assert is_blacklisted is False
        assert key not in connected_mock_redis.data  # Should be cleaned up


@pytest.mark.unit
class TestRefreshTokenManagement:
    """Test refresh token session management"""
    
    async def test_store_refresh_token(self, connected_mock_redis):
        """Test storing refresh token metadata"""
        token_jti = "refresh_123"
        user_id = "user_456"
        session_data = {
            "ip_address": "127.0.0.1",
            "user_agent": "Mozilla/5.0",
            "login_method": "oauth"
        }
        
        await connected_mock_redis.store_refresh_token(token_jti, user_id, session_data)
        
        # Verify refresh token was stored
        key = f"refresh_token:{token_jti}"
        assert key in connected_mock_redis.data
        stored_data = connected_mock_redis.data[key]
        assert stored_data["user_id"] == user_id
        assert stored_data["ip_address"] == session_data["ip_address"]
        assert "created_at" in stored_data
        assert "last_used" in stored_data
        
    async def test_get_refresh_token_valid(self, connected_mock_redis):
        """Test retrieving valid refresh token"""
        token_jti = "refresh_123"
        user_id = "user_456"
        session_data = {"ip_address": "127.0.0.1"}
        
        await connected_mock_redis.store_refresh_token(token_jti, user_id, session_data)
        retrieved_data = await connected_mock_redis.get_refresh_token(token_jti)
        
        assert retrieved_data is not None
        assert retrieved_data["user_id"] == user_id
        assert retrieved_data["ip_address"] == session_data["ip_address"]
        
    async def test_get_refresh_token_not_found(self, connected_mock_redis):
        """Test retrieving non-existent refresh token"""
        retrieved_data = await connected_mock_redis.get_refresh_token("nonexistent")
        assert retrieved_data is None
        
    async def test_update_refresh_token_usage(self, connected_mock_redis):
        """Test updating refresh token last used time"""
        token_jti = "refresh_123"
        user_id = "user_456"
        
        await connected_mock_redis.store_refresh_token(token_jti, user_id, {})
        original_last_used = connected_mock_redis.data[f"refresh_token:{token_jti}"]["last_used"]
        
        # Wait a bit to ensure timestamp difference
        await asyncio.sleep(0.01)
        
        await connected_mock_redis.update_refresh_token_usage(token_jti)
        updated_last_used = connected_mock_redis.data[f"refresh_token:{token_jti}"]["last_used"]
        
        assert updated_last_used != original_last_used
        
    async def test_revoke_refresh_token(self, connected_mock_redis):
        """Test revoking single refresh token"""
        token_jti = "refresh_123"
        user_id = "user_456"
        
        await connected_mock_redis.store_refresh_token(token_jti, user_id, {})
        assert f"refresh_token:{token_jti}" in connected_mock_redis.data
        
        await connected_mock_redis.revoke_refresh_token(token_jti)
        assert f"refresh_token:{token_jti}" not in connected_mock_redis.data
        
    async def test_revoke_all_user_tokens(self, connected_mock_redis):
        """Test revoking all tokens for a user"""
        user_id = "user_456"
        
        # Store multiple refresh tokens for the user
        await connected_mock_redis.store_refresh_token("refresh_1", user_id, {})
        await connected_mock_redis.store_refresh_token("refresh_2", user_id, {})
        await connected_mock_redis.store_refresh_token("refresh_3", "other_user", {})
        
        revoked_count = await connected_mock_redis.revoke_all_user_tokens(user_id)
        
        assert revoked_count == 2
        assert "refresh_token:refresh_1" not in connected_mock_redis.data
        assert "refresh_token:refresh_2" not in connected_mock_redis.data
        assert "refresh_token:refresh_3" in connected_mock_redis.data  # Other user's token preserved
        
    async def test_get_user_sessions(self, connected_mock_redis):
        """Test getting all sessions for a user"""
        user_id = "user_456"
        
        await connected_mock_redis.store_refresh_token("refresh_1", user_id, {"ip": "127.0.0.1"})
        await connected_mock_redis.store_refresh_token("refresh_2", user_id, {"ip": "192.168.1.1"})
        await connected_mock_redis.store_refresh_token("refresh_3", "other_user", {"ip": "10.0.0.1"})
        
        sessions = await connected_mock_redis.get_user_sessions(user_id)
        
        assert len(sessions) == 2
        assert all(session["user_id"] == user_id for session in sessions)


@pytest.mark.unit
class TestGeneralCaching:
    """Test general caching functionality"""
    
    async def test_set_cache_string(self, connected_mock_redis):
        """Test caching string value"""
        key = "test_key"
        value = "test_value"
        
        await connected_mock_redis.set_cache(key, value, ttl=3600)
        
        assert key in connected_mock_redis.data
        assert connected_mock_redis.data[key]["data"] == value
        
    async def test_set_cache_dict(self, connected_mock_redis):
        """Test caching dictionary value"""
        key = "test_dict"
        value = {"key1": "value1", "key2": "value2"}
        
        await connected_mock_redis.set_cache(key, value, ttl=3600)
        
        assert key in connected_mock_redis.data
        stored_value = json.loads(connected_mock_redis.data[key]["data"])
        assert stored_value == value
        
    async def test_get_cache_valid(self, connected_mock_redis):
        """Test retrieving valid cached value"""
        key = "test_key"
        value = "test_value"
        
        await connected_mock_redis.set_cache(key, value)
        retrieved_value = await connected_mock_redis.get_cache(key)
        
        assert retrieved_value == value
        
    async def test_get_cache_not_found(self, connected_mock_redis):
        """Test retrieving non-existent cached value"""
        retrieved_value = await connected_mock_redis.get_cache("nonexistent")
        assert retrieved_value is None
        
    async def test_delete_cache(self, connected_mock_redis):
        """Test deleting cached value"""
        key = "test_key"
        value = "test_value"
        
        await connected_mock_redis.set_cache(key, value)
        assert key in connected_mock_redis.data
        
        deleted = await connected_mock_redis.delete_cache(key)
        assert deleted is True
        assert key not in connected_mock_redis.data
        
    async def test_delete_cache_not_found(self, connected_mock_redis):
        """Test deleting non-existent cached value"""
        deleted = await connected_mock_redis.delete_cache("nonexistent")
        assert deleted is False


@pytest.mark.unit  
class TestCountersAndAnalytics:
    """Test counters and analytics functionality"""
    
    async def test_increment_counter_new(self, connected_mock_redis):
        """Test incrementing new counter"""
        key = "test_counter"
        
        count = await connected_mock_redis.increment_counter(key)
        
        assert count == 1
        assert connected_mock_redis.counters[key] == 1
        
    async def test_increment_counter_existing(self, connected_mock_redis):
        """Test incrementing existing counter"""
        key = "test_counter"
        
        await connected_mock_redis.increment_counter(key)
        count = await connected_mock_redis.increment_counter(key)
        
        assert count == 2
        assert connected_mock_redis.counters[key] == 2
        
    async def test_get_stats(self, connected_mock_redis):
        """Test getting Redis statistics"""
        # Add some test data
        await connected_mock_redis.set_oauth_state("state1", {"user": "test"})
        await connected_mock_redis.store_refresh_token("refresh1", "user1", {})
        await connected_mock_redis.blacklist_token("token1", datetime.utcnow() + timedelta(hours=1))
        await connected_mock_redis.set_keycloak_jwks({"keys": []})
        
        stats = await connected_mock_redis.get_stats()
        
        assert stats["redis_version"] == "7.0.0-mock"
        assert stats["oauth_states"] == 1
        assert stats["refresh_tokens"] == 1
        assert stats["blacklisted_tokens"] == 1
        assert stats["jwks_cached"] is True
        
    async def test_get_stats_empty(self, connected_mock_redis):
        """Test getting stats with no data"""
        stats = await connected_mock_redis.get_stats()
        
        assert stats["oauth_states"] == 0
        assert stats["refresh_tokens"] == 0
        assert stats["blacklisted_tokens"] == 0
        assert stats["jwks_cached"] is False


@pytest.mark.unit
class TestRealRedisClient:
    """Test real Redis client with mocked aioredis"""
    
    @patch('redis.asyncio.from_url')
    async def test_real_redis_connect_success(self, mock_from_url):
        """Test connecting to real Redis (mocked)"""
        # Mock aioredis connection
        mock_redis = AsyncMock()
        mock_redis.ping.return_value = None
        mock_from_url.return_value = mock_redis
        
        client = RedisClient()
        await client.connect()
        
        assert client.redis == mock_redis
        mock_redis.ping.assert_called_once()
        
    @patch('redis.asyncio.from_url')
    async def test_real_redis_connect_failure(self, mock_from_url):
        """Test Redis connection failure"""
        mock_from_url.side_effect = Exception("Connection failed")
        
        client = RedisClient()
        
        with pytest.raises(Exception, match="Connection failed"):
            await client.connect()
            
    async def test_real_redis_disconnect(self):
        """Test Redis disconnection"""
        client = RedisClient()
        client.redis = AsyncMock()
        
        await client.disconnect()
        
        client.redis.close.assert_called_once()