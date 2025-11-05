"""
Unit tests for authentication dependencies

Tests:
1. KeycloakJWTBearer class functionality
2. JWT token verification and validation
3. JWKS caching with Redis
4. Token blacklist checking
5. User info extraction from JWT
6. FastAPI dependency functions
7. Role-based access control (RBAC)
8. Error handling and security
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

from app.auth.dependencies import (
    KeycloakJWTBearer,
    get_current_user,
    get_optional_user,
    require_roles,
    require_all_roles,
    revoke_token,
    revoke_all_user_tokens,
    get_user_sessions
)
from app.core.config import settings


@pytest.mark.unit
class TestKeycloakJWTBearer:
    """Test KeycloakJWTBearer class functionality"""
    
    def test_init(self, connected_mock_redis):
        """Test KeycloakJWTBearer initialization"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        assert bearer.keycloak_url == settings.keycloak_url
        assert bearer.realm == settings.keycloak_realm
        assert bearer.client_id == settings.keycloak_client_id
        assert bearer.redis == connected_mock_redis
        
    async def test_get_public_key_cached(self, connected_mock_redis, mock_keycloak_jwks):
        """Test getting public key from Redis cache"""
        # Pre-cache JWKS
        await connected_mock_redis.set_keycloak_jwks(mock_keycloak_jwks)
        
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        with patch('cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers') as mock_rsa:
            mock_key = MagicMock()
            mock_key.public_bytes.return_value = b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
            mock_rsa.return_value.public_key.return_value = mock_key
            
            public_key = await bearer.get_public_key()
            
            assert "BEGIN PUBLIC KEY" in public_key
            # Should not make HTTP request since JWKS is cached
            
    async def test_get_public_key_fetch_from_keycloak(
        self, 
        connected_mock_redis, 
        mock_keycloak_jwks,
        mock_httpx_keycloak
    ):
        """Test fetching public key from Keycloak when not cached"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        with patch('cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers') as mock_rsa:
            mock_key = MagicMock()
            mock_key.public_bytes.return_value = b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
            mock_rsa.return_value.public_key.return_value = mock_key
            
            public_key = await bearer.get_public_key()
            
            assert "BEGIN PUBLIC KEY" in public_key
            # Verify JWKS was cached after fetching
            cached_jwks = await connected_mock_redis.get_keycloak_jwks()
            assert cached_jwks == mock_keycloak_jwks
            
    async def test_get_public_key_keycloak_error(self, connected_mock_redis):
        """Test handling Keycloak error when fetching JWKS"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = Exception("Network error")
            mock_instance.__aenter__.return_value = mock_instance
            mock_client.return_value = mock_instance
            
            with pytest.raises(HTTPException) as exc_info:
                await bearer.get_public_key()
                
            assert exc_info.value.status_code == 503
            assert "Error getting public key" in str(exc_info.value.detail)
            
    async def test_verify_token_valid(
        self, 
        connected_mock_redis, 
        test_jwt_token, 
        test_public_key,
        test_user_data
    ):
        """Test verifying valid JWT token"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        # Mock get_public_key to return test key
        with patch.object(bearer, 'get_public_key', return_value=test_public_key):
            payload = await bearer.verify_token(test_jwt_token)
            
            assert payload["sub"] == test_user_data["sub"]
            assert payload["preferred_username"] == test_user_data["preferred_username"]
            assert payload["iss"] == test_user_data["iss"]
            
    async def test_verify_token_blacklisted(
        self, 
        connected_mock_redis, 
        test_jwt_token,
        test_public_key
    ):
        """Test verifying blacklisted token"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        # Blacklist the token
        await connected_mock_redis.blacklist_token("token_123", datetime.utcnow() + timedelta(hours=1))
        
        with patch.object(bearer, 'get_public_key', return_value=test_public_key):
            with pytest.raises(HTTPException) as exc_info:
                await bearer.verify_token(test_jwt_token)
                
            assert exc_info.value.status_code == 401
            assert "revoked" in str(exc_info.value.detail)
            
    async def test_verify_token_expired(
        self, 
        connected_mock_redis, 
        expired_jwt_token,
        test_public_key
    ):
        """Test verifying expired JWT token"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        with patch.object(bearer, 'get_public_key', return_value=test_public_key):
            with pytest.raises(HTTPException) as exc_info:
                await bearer.verify_token(expired_jwt_token)
                
            assert exc_info.value.status_code == 401
            assert "expired" in str(exc_info.value.detail).lower()
            
    async def test_verify_token_invalid_audience(
        self, 
        connected_mock_redis, 
        test_private_key,
        test_public_key,
        test_user_data
    ):
        """Test verifying token with invalid audience"""
        # Create token with wrong audience
        invalid_data = test_user_data.copy()
        invalid_data["aud"] = "wrong_client_id"
        invalid_token = jwt.encode(invalid_data, test_private_key, algorithm="RS256")
        
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        with patch.object(bearer, 'get_public_key', return_value=test_public_key):
            with pytest.raises(HTTPException) as exc_info:
                await bearer.verify_token(invalid_token)
                
            assert exc_info.value.status_code == 401
            assert "audience" in str(exc_info.value.detail)
            
    async def test_verify_token_invalid_issuer(
        self, 
        connected_mock_redis, 
        test_private_key,
        test_public_key,
        test_user_data
    ):
        """Test verifying token with invalid issuer"""
        # Create token with wrong issuer
        invalid_data = test_user_data.copy()
        invalid_data["iss"] = "wrong_issuer"
        invalid_token = jwt.encode(invalid_data, test_private_key, algorithm="RS256")
        
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        with patch.object(bearer, 'get_public_key', return_value=test_public_key):
            with pytest.raises(HTTPException) as exc_info:
                await bearer.verify_token(invalid_token)
                
            assert exc_info.value.status_code == 401
            assert "issuer" in str(exc_info.value.detail)
            
    async def test_get_user_info(
        self, 
        connected_mock_redis, 
        test_jwt_token,
        test_public_key,
        test_user_data
    ):
        """Test extracting user info from JWT token"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        with patch.object(bearer, 'verify_token', return_value=test_user_data):
            user_info = await bearer.get_user_info(test_jwt_token)
            
            assert user_info["user_id"] == test_user_data["sub"]
            assert user_info["username"] == test_user_data["preferred_username"]
            assert user_info["email"] == test_user_data["email"]
            assert user_info["name"] == test_user_data["name"]
            assert user_info["given_name"] == test_user_data["given_name"]
            assert user_info["family_name"] == test_user_data["family_name"]
            
            # Check roles extraction
            expected_roles = ["user", "manager", "finance_user"]  # From realm + client
            assert set(user_info["roles"]) == set(expected_roles)
            
            assert user_info["groups"] == test_user_data["groups"]
            assert user_info["session_id"] == test_user_data["sid"]
            assert user_info["token_jti"] == test_user_data["jti"]


@pytest.mark.unit
class TestDependencyFunctions:
    """Test FastAPI dependency functions"""
    
    async def test_get_current_user_valid(
        self, 
        connected_mock_redis,
        test_jwt_token,
        test_user_data
    ):
        """Test get_current_user with valid token"""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=test_jwt_token
        )
        
        # Mock KeycloakJWTBearer.get_user_info
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": test_user_data["sub"],
                "username": test_user_data["preferred_username"],
                "roles": ["user"]
            }
            mock_bearer_class.return_value = mock_bearer
            
            user_info = await get_current_user(credentials, connected_mock_redis)
            
            assert user_info["user_id"] == test_user_data["sub"]
            assert user_info["username"] == test_user_data["preferred_username"]
            mock_bearer.get_user_info.assert_called_once_with(test_jwt_token)
            
    async def test_get_current_user_no_credentials(self, connected_mock_redis):
        """Test get_current_user without credentials"""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(None, connected_mock_redis)
            
        assert exc_info.value.status_code == 401
        assert "Authorization required" in str(exc_info.value.detail)
        
    async def test_get_current_user_invalid_token(
        self, 
        connected_mock_redis,
        test_jwt_token
    ):
        """Test get_current_user with invalid token"""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=test_jwt_token
        )
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.side_effect = HTTPException(
                status_code=401,
                detail="Invalid token"
            )
            mock_bearer_class.return_value = mock_bearer
            
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials, connected_mock_redis)
                
            assert exc_info.value.status_code == 401
            
    async def test_get_optional_user_valid(
        self, 
        connected_mock_redis,
        test_jwt_token,
        test_user_data
    ):
        """Test get_optional_user with valid token"""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=test_jwt_token
        )
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": test_user_data["sub"],
                "username": test_user_data["preferred_username"]
            }
            mock_bearer_class.return_value = mock_bearer
            
            user_info = await get_optional_user(credentials, connected_mock_redis)
            
            assert user_info is not None
            assert user_info["user_id"] == test_user_data["sub"]
            
    async def test_get_optional_user_no_credentials(self, connected_mock_redis):
        """Test get_optional_user without credentials"""
        user_info = await get_optional_user(None, connected_mock_redis)
        assert user_info is None
        
    async def test_get_optional_user_invalid_token(
        self, 
        connected_mock_redis,
        test_jwt_token
    ):
        """Test get_optional_user with invalid token"""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=test_jwt_token
        )
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.side_effect = HTTPException(
                status_code=401,
                detail="Invalid token"
            )
            mock_bearer_class.return_value = mock_bearer
            
            user_info = await get_optional_user(credentials, connected_mock_redis)
            assert user_info is None


@pytest.mark.unit
class TestRoleBasedAccessControl:
    """Test role-based access control (RBAC)"""
    
    async def test_require_roles_has_required_role(self):
        """Test require_roles when user has required role"""
        user_data = {
            "user_id": "user_123",
            "username": "testuser",
            "roles": ["user", "manager"]
        }
        
        # Create dependency function
        check_roles = require_roles(["manager", "admin"])
        
        # Mock get_current_user
        with patch('app.auth.dependencies.get_current_user', return_value=user_data):
            result = await check_roles()
            
        assert result == user_data
        
    async def test_require_roles_missing_required_role(self):
        """Test require_roles when user lacks required role"""
        user_data = {
            "user_id": "user_123",
            "username": "testuser", 
            "roles": ["user"]
        }
        
        check_roles = require_roles(["admin"])
        
        with patch('app.auth.dependencies.get_current_user', return_value=user_data):
            with pytest.raises(HTTPException) as exc_info:
                await check_roles()
                
        assert exc_info.value.status_code == 403
        assert "Required roles" in str(exc_info.value.detail)
        assert "admin" in str(exc_info.value.detail)
        
    async def test_require_roles_no_roles(self):
        """Test require_roles when user has no roles"""
        user_data = {
            "user_id": "user_123",
            "username": "testuser",
            "roles": []
        }
        
        check_roles = require_roles(["user"])
        
        with patch('app.auth.dependencies.get_current_user', return_value=user_data):
            with pytest.raises(HTTPException) as exc_info:
                await check_roles()
                
        assert exc_info.value.status_code == 403
        
    async def test_require_all_roles_has_all_roles(self):
        """Test require_all_roles when user has all required roles"""
        user_data = {
            "user_id": "user_123",
            "username": "testuser",
            "roles": ["user", "manager", "admin"]
        }
        
        check_all_roles = require_all_roles(["user", "manager"])
        
        with patch('app.auth.dependencies.get_current_user', return_value=user_data):
            result = await check_all_roles()
            
        assert result == user_data
        
    async def test_require_all_roles_missing_some_roles(self):
        """Test require_all_roles when user lacks some required roles"""
        user_data = {
            "user_id": "user_123",
            "username": "testuser",
            "roles": ["user"]
        }
        
        check_all_roles = require_all_roles(["user", "manager", "admin"])
        
        with patch('app.auth.dependencies.get_current_user', return_value=user_data):
            with pytest.raises(HTTPException) as exc_info:
                await check_all_roles()
                
        assert exc_info.value.status_code == 403
        assert "Missing" in str(exc_info.value.detail)
        assert "manager" in str(exc_info.value.detail)
        assert "admin" in str(exc_info.value.detail)


@pytest.mark.unit
class TestTokenManagementFunctions:
    """Test token management utility functions"""
    
    async def test_revoke_token(self, connected_mock_redis):
        """Test revoking single token"""
        token_jti = "token_123"
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        await revoke_token(token_jti, expires_at, connected_mock_redis)
        
        # Verify token was blacklisted
        is_blacklisted = await connected_mock_redis.is_token_blacklisted(token_jti)
        assert is_blacklisted is True
        
    async def test_revoke_all_user_tokens(self, connected_mock_redis):
        """Test revoking all tokens for a user"""
        user_id = "user_123"
        
        # Store some refresh tokens
        await connected_mock_redis.store_refresh_token("refresh_1", user_id, {})
        await connected_mock_redis.store_refresh_token("refresh_2", user_id, {})
        await connected_mock_redis.store_refresh_token("refresh_3", "other_user", {})
        
        revoked_count = await revoke_all_user_tokens(user_id, connected_mock_redis)
        
        assert revoked_count == 2
        
        # Verify correct tokens were revoked
        token_1 = await connected_mock_redis.get_refresh_token("refresh_1")
        token_2 = await connected_mock_redis.get_refresh_token("refresh_2")
        token_3 = await connected_mock_redis.get_refresh_token("refresh_3")
        
        assert token_1 is None
        assert token_2 is None
        assert token_3 is not None  # Other user's token preserved
        
    async def test_get_user_sessions(self, connected_mock_redis):
        """Test getting user sessions"""
        user_id = "user_123"
        
        # Store sessions
        session_data_1 = {"ip_address": "127.0.0.1", "user_agent": "Chrome"}
        session_data_2 = {"ip_address": "192.168.1.1", "user_agent": "Firefox"}
        
        await connected_mock_redis.store_refresh_token("refresh_1", user_id, session_data_1)
        await connected_mock_redis.store_refresh_token("refresh_2", user_id, session_data_2)
        await connected_mock_redis.store_refresh_token("refresh_3", "other_user", {})
        
        sessions = await get_user_sessions(user_id, connected_mock_redis)
        
        assert len(sessions) == 2
        assert all(session["user_id"] == user_id for session in sessions)
        
        # Check session data is preserved
        ip_addresses = [session["ip_address"] for session in sessions]
        assert "127.0.0.1" in ip_addresses
        assert "192.168.1.1" in ip_addresses


@pytest.mark.unit
class TestErrorHandling:
    """Test error handling in auth dependencies"""
    
    async def test_jwt_bearer_network_error(self, connected_mock_redis):
        """Test handling network errors when contacting Keycloak"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = Exception("Network timeout")
            mock_instance.__aenter__.return_value = mock_instance
            mock_client.return_value = mock_instance
            
            with pytest.raises(HTTPException) as exc_info:
                await bearer.get_public_key()
                
            assert exc_info.value.status_code == 503
            
    async def test_get_current_user_unexpected_error(self, connected_mock_redis):
        """Test handling unexpected errors in get_current_user"""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="test_token"
        )
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer_class.side_effect = Exception("Unexpected error")
            
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials, connected_mock_redis)
                
            assert exc_info.value.status_code == 500
            assert "Internal authentication error" in str(exc_info.value.detail)


@pytest.mark.unit
class TestBase64UrlDecoding:
    """Test base64url decoding helper function"""
    
    def test_base64url_decode_no_padding(self, connected_mock_redis):
        """Test decoding base64url without padding"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        # "hello" in base64url
        encoded = "aGVsbG8"
        decoded = bearer._base64url_decode(encoded)
        
        assert decoded == b"hello"
        
    def test_base64url_decode_with_padding(self, connected_mock_redis):
        """Test decoding base64url that needs padding"""
        bearer = KeycloakJWTBearer(connected_mock_redis)
        
        # "hi" in base64url (needs padding)
        encoded = "aGk"
        decoded = bearer._base64url_decode(encoded)
        
        assert decoded == b"hi"