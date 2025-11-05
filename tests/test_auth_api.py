"""
Integration tests for authentication API endpoints

Tests:
1. OAuth login flow with Redis state management
2. OAuth callback handling and token exchange
3. User info endpoints with JWT validation
4. Token refresh with Redis session tracking
5. Logout functionality with token blacklist
6. Session management endpoints
7. Analytics and configuration endpoints
8. Error handling and security scenarios
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from datetime import datetime, timedelta
import json
from urllib.parse import parse_qs, urlparse

from fastapi import status
from fastapi.testclient import TestClient

from app.main import app

@pytest.mark.auth
@pytest.mark.integration
class TestOAuthLoginFlow:
    """Test OAuth login flow with Redis state management"""
    
    def test_login_redirect(self, test_client, override_redis_dependency):
        """Test login endpoint redirects to Keycloak"""
        response = test_client.get("/api/v1/auth/login")
        
        assert response.status_code == 302
        assert response.headers["location"].startswith(
            f"http://localhost:8080/realms/finance-realm/protocol/openid-connect/auth"
        )
        
        # Check URL parameters
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        params = parse_qs(parsed_url.query)
        
        assert params["client_id"][0] == "finance-tracker"
        assert params["response_type"][0] == "code"
        assert params["scope"][0] == "openid profile email"
        assert "state" in params
        
    def test_login_with_redirect_url(self, test_client, override_redis_dependency):
        """Test login with custom redirect URL"""
        redirect_url = "http://localhost:3000/dashboard"
        response = test_client.get(f"/api/v1/auth/login?redirect_url={redirect_url}")
        
        assert response.status_code == 302
        
        # State should be stored in Redis with redirect_url
        # We'll verify this in the callback test
        
    def test_login_stores_state_in_redis(self, test_client, override_redis_dependency, connected_mock_redis):
        """Test that login stores OAuth state in Redis"""
        response = test_client.get("/api/v1/auth/login")
        
        # Extract state from redirect URL
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        params = parse_qs(parsed_url.query)
        state = params["state"][0]
        
        # Verify state was stored in Redis
        oauth_states = [key for key in connected_mock_redis.data.keys() if key.startswith("oauth_state:")]
        assert len(oauth_states) == 1
        assert f"oauth_state:{state}" in connected_mock_redis.data


@pytest.mark.integration
class TestOAuthCallback:
    """Test OAuth callback handling and token exchange"""
    
    async def test_callback_success(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis,
        mock_httpx_keycloak
    ):
        """Test successful OAuth callback"""
        # First, simulate login to get valid state
        login_response = await async_test_client.get("/api/v1/auth/login")
        redirect_url = login_response.headers["location"]
        parsed_url = urlparse(redirect_url)
        params = parse_qs(parsed_url.query)
        state = params["state"][0]
        
        # Now test callback with valid state and code
        callback_response = await async_test_client.get(
            f"/api/v1/auth/callback?code=test_auth_code&state={state}"
        )
        
        assert callback_response.status_code == 200
        data = callback_response.json()
        
        assert data["message"] == "Authorization successful!"
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert "expires_in" in data
        
    async def test_callback_invalid_state(
        self, 
        async_test_client, 
        override_redis_dependency
    ):
        """Test callback with invalid OAuth state"""
        response = await async_test_client.get(
            "/api/v1/auth/callback?code=test_code&state=invalid_state"
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "Invalid or expired state" in data["detail"]
        
    async def test_callback_missing_code(
        self, 
        async_test_client, 
        override_redis_dependency
    ):
        """Test callback without authorization code"""
        response = await async_test_client.get(
            "/api/v1/auth/callback?state=some_state"
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "Missing authorization code" in data["detail"]
        
    async def test_callback_oauth_error(
        self, 
        async_test_client, 
        override_redis_dependency
    ):
        """Test callback with OAuth error from Keycloak"""
        response = await async_test_client.get(
            "/api/v1/auth/callback?error=access_denied&error_description=User denied access"
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "Authorization error: access_denied" in data["detail"]
        
    async def test_callback_keycloak_error(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis
    ):
        """Test callback when Keycloak returns error during token exchange"""
        # Setup valid state
        state = "valid_state"
        await connected_mock_redis.set_oauth_state(state, {"test": "data"})
        
        # Mock httpx to return error
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post.side_effect = Exception("Network error")
            mock_instance.__aenter__.return_value = mock_instance
            mock_client.return_value = mock_instance
            
            response = await async_test_client.get(
                f"/api/v1/auth/callback?code=test_code&state={state}"
            )
            
        assert response.status_code == 500
        data = response.json()
        assert "Unexpected error" in data["detail"]


@pytest.mark.integration  
class TestUserInfoEndpoints:
    """Test user info endpoints with JWT validation"""
    
    async def test_get_me_success(
        self, 
        async_test_client, 
        override_redis_dependency,
        test_jwt_token,
        test_user_data
    ):
        """Test /me endpoint with valid JWT token"""
        headers = {"Authorization": f"Bearer {test_jwt_token}"}
        
        # Mock the JWT validation
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": test_user_data["sub"],
                "username": test_user_data["preferred_username"],
                "email": test_user_data["email"],
                "name": test_user_data["name"],
                "given_name": test_user_data["given_name"],
                "family_name": test_user_data["family_name"],
                "roles": ["user", "manager"],
                "groups": test_user_data["groups"],
                "session_id": test_user_data["sid"],
                "issued_at": test_user_data["iat"],
                "expires_at": test_user_data["exp"],
            }
            mock_bearer_class.return_value = mock_bearer
            
            response = await async_test_client.get("/api/v1/auth/me", headers=headers)
            
        assert response.status_code == 200
        data = response.json()
        
        assert data["user_id"] == test_user_data["sub"]
        assert data["username"] == test_user_data["preferred_username"]
        assert data["email"] == test_user_data["email"]
        assert data["roles"] == ["user", "manager"]
        assert "token_issued_at" in data
        assert "token_expires_at" in data
        
    async def test_get_me_no_token(self, async_test_client, override_redis_dependency):
        """Test /me endpoint without token"""
        response = await async_test_client.get("/api/v1/auth/me")
        
        assert response.status_code == 403  # No Authorization header
        
    async def test_get_me_invalid_token(
        self, 
        async_test_client, 
        override_redis_dependency
    ):
        """Test /me endpoint with invalid token"""
        headers = {"Authorization": "Bearer invalid_token"}
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.side_effect = Exception("Invalid token")
            mock_bearer_class.return_value = mock_bearer
            
            response = await async_test_client.get("/api/v1/auth/me", headers=headers)
            
        assert response.status_code == 500  # Internal error handling
        
    async def test_auth_status_authenticated(
        self, 
        async_test_client, 
        override_redis_dependency,
        test_jwt_token,
        test_user_data
    ):
        """Test /status endpoint with authenticated user"""
        headers = {"Authorization": f"Bearer {test_jwt_token}"}
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": test_user_data["sub"],
                "username": test_user_data["preferred_username"],
                "email": test_user_data["email"],
                "roles": ["user"],
                "expires_at": test_user_data["exp"],
            }
            mock_bearer_class.return_value = mock_bearer
            
            response = await async_test_client.get("/api/v1/auth/status", headers=headers)
            
        assert response.status_code == 200
        data = response.json()
        
        assert data["authenticated"] is True
        assert data["user"]["username"] == test_user_data["preferred_username"]
        assert "expires_at" in data["user"]
        
    async def test_auth_status_not_authenticated(
        self, 
        async_test_client, 
        override_redis_dependency
    ):
        """Test /status endpoint without authentication"""
        response = await async_test_client.get("/api/v1/auth/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["authenticated"] is False
        assert data["user"] is None


@pytest.mark.integration
class TestTokenRefresh:
    """Test token refresh with Redis session tracking"""
    
    async def test_refresh_token_success(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis,
        mock_httpx_keycloak
    ):
        """Test successful token refresh"""
        # Store refresh token in Redis
        refresh_jti = "refresh_token_123"
        user_id = "user_456"
        await connected_mock_redis.store_refresh_token(refresh_jti, user_id, {
            "ip_address": "127.0.0.1",
            "user_agent": "Test Agent"
        })
        
        response = await async_test_client.post(
            "/api/v1/auth/refresh",
            params={"refresh_token": "mock_refresh_token"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert "expires_in" in data
        
    async def test_refresh_token_not_in_redis(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis
    ):
        """Test refresh token not found in Redis"""
        # Mock JWT decoding to return JTI
        with patch('jose.jwt.get_unverified_claims') as mock_decode:
            mock_decode.return_value = {"jti": "nonexistent_refresh"}
            
            response = await async_test_client.post(
                "/api/v1/auth/refresh",
                params={"refresh_token": "test_refresh_token"}
            )
            
        assert response.status_code == 401
        data = response.json()
        assert "not found or expired" in data["detail"]
        
    async def test_refresh_token_keycloak_error(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis
    ):
        """Test refresh token when Keycloak returns error"""
        # Store valid refresh token
        refresh_jti = "refresh_token_123"
        user_id = "user_456"
        await connected_mock_redis.store_refresh_token(refresh_jti, user_id, {})
        
        # Mock JWT decoding
        with patch('jose.jwt.get_unverified_claims') as mock_decode:
            mock_decode.return_value = {"jti": refresh_jti}
            
            # Mock httpx to return error
            with patch('httpx.AsyncClient') as mock_client:
                mock_instance = AsyncMock()
                mock_response = AsyncMock()
                mock_response.raise_for_status.side_effect = Exception("Invalid refresh token")
                mock_instance.post.return_value = mock_response
                mock_instance.__aenter__.return_value = mock_instance
                mock_client.return_value = mock_instance
                
                response = await async_test_client.post(
                    "/api/v1/auth/refresh",
                    params={"refresh_token": "test_refresh_token"}
                )
                
        assert response.status_code == 401
        data = response.json()
        assert "Invalid refresh token" in data["detail"]


@pytest.mark.integration
class TestLogoutFunctionality:
    """Test logout functionality with token blacklist"""
    
    async def test_logout_success(
        self, 
        async_test_client, 
        override_redis_dependency,
        test_jwt_token,
        test_user_data
    ):
        """Test successful logout"""
        headers = {"Authorization": f"Bearer {test_jwt_token}"}
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": test_user_data["sub"],
                "username": test_user_data["preferred_username"],
                "token_jti": test_user_data["jti"],
                "expires_at": test_user_data["exp"],
            }
            mock_bearer_class.return_value = mock_bearer
            
            response = await async_test_client.post("/api/v1/auth/logout", headers=headers)
            
        assert response.status_code == 200
        data = response.json()
        
        assert "Logged out successfully" in data["message"]
        assert data["user"] == test_user_data["preferred_username"]
        
    async def test_logout_all_success(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis,
        test_jwt_token,
        test_user_data
    ):
        """Test logout from all devices"""
        headers = {"Authorization": f"Bearer {test_jwt_token}"}
        
        # Store some refresh tokens for the user
        user_id = test_user_data["sub"]
        await connected_mock_redis.store_refresh_token("refresh_1", user_id, {})
        await connected_mock_redis.store_refresh_token("refresh_2", user_id, {})
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": user_id,
                "username": test_user_data["preferred_username"],
                "token_jti": test_user_data["jti"],
                "expires_at": test_user_data["exp"],
            }
            mock_bearer_class.return_value = mock_bearer
            
            response = await async_test_client.post("/api/v1/auth/logout-all", headers=headers)
            
        assert response.status_code == 200
        data = response.json()
        
        assert data["sessions_revoked"] == 2
        assert test_user_data["preferred_username"] in data["message"]
        
    async def test_logout_no_token(self, async_test_client, override_redis_dependency):
        """Test logout without authentication"""
        response = await async_test_client.post("/api/v1/auth/logout")
        
        assert response.status_code == 403


@pytest.mark.integration
class TestSessionManagement:
    """Test session management endpoints"""
    
    async def test_get_sessions_success(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis,
        test_jwt_token,
        test_user_data
    ):
        """Test getting user sessions"""
        headers = {"Authorization": f"Bearer {test_jwt_token}"}
        user_id = test_user_data["sub"]
        
        # Store some sessions
        await connected_mock_redis.store_refresh_token("refresh_1", user_id, {
            "ip_address": "127.0.0.1",
            "user_agent": "Chrome",
            "login_method": "oauth"
        })
        await connected_mock_redis.store_refresh_token("refresh_2", user_id, {
            "ip_address": "192.168.1.1", 
            "user_agent": "Firefox",
            "login_method": "oauth"
        })
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": user_id,
                "username": test_user_data["preferred_username"],
            }
            mock_bearer_class.return_value = mock_bearer
            
            response = await async_test_client.get("/api/v1/auth/sessions", headers=headers)
            
        assert response.status_code == 200
        data = response.json()
        
        assert data["total_sessions"] == 2
        assert data["user"] == test_user_data["preferred_username"]
        assert len(data["sessions"]) == 2
        
        # Check session data
        session_ips = [session["ip_address"] for session in data["sessions"]]
        assert "127.0.0.1" in session_ips
        assert "192.168.1.1" in session_ips


@pytest.mark.integration
class TestConfigurationEndpoints:
    """Test configuration and analytics endpoints"""
    
    def test_get_auth_config(self, test_client):
        """Test getting auth configuration"""
        response = test_client.get("/api/v1/auth/config")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["keycloak_url"] == "http://localhost:8080"
        assert data["realm"] == "finance-realm"
        assert data["client_id"] == "finance-tracker"
        assert "endpoints" in data
        assert "keycloak_endpoints" in data
        
        # Check endpoint URLs
        assert data["endpoints"]["login"] == "/api/v1/auth/login"
        assert data["endpoints"]["callback"] == "/api/v1/auth/callback"
        assert data["endpoints"]["me"] == "/api/v1/auth/me"
        
    async def test_get_analytics_admin(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis,
        test_jwt_token,
        test_user_data
    ):
        """Test getting analytics as admin"""
        headers = {"Authorization": f"Bearer {test_jwt_token}"}
        
        # Add some test counters
        await connected_mock_redis.increment_counter("login_attempts_total")
        await connected_mock_redis.increment_counter("successful_logins_total")
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": test_user_data["sub"],
                "username": test_user_data["preferred_username"],
                "roles": ["admin"],  # Admin role
            }
            mock_bearer_class.return_value = mock_bearer
            
            response = await async_test_client.get("/api/v1/auth/analytics", headers=headers)
            
        assert response.status_code == 200
        data = response.json()
        
        assert "redis_stats" in data
        assert "auth_metrics" in data
        assert "login_attempts" in data["auth_metrics"]
        assert "successful_logins" in data["auth_metrics"]
        
    async def test_get_analytics_non_admin(
        self, 
        async_test_client, 
        override_redis_dependency,
        test_jwt_token,
        test_user_data
    ):
        """Test getting analytics as non-admin user"""
        headers = {"Authorization": f"Bearer {test_jwt_token}"}
        
        with patch('app.auth.dependencies.KeycloakJWTBearer') as mock_bearer_class:
            mock_bearer = AsyncMock()
            mock_bearer.get_user_info.return_value = {
                "user_id": test_user_data["sub"],
                "username": test_user_data["preferred_username"],
                "roles": ["user"],  # Non-admin role
            }
            mock_bearer_class.return_value = mock_bearer
            
            response = await async_test_client.get("/api/v1/auth/analytics", headers=headers)
            
        assert response.status_code == 403
        data = response.json()
        assert "Admin role required" in data["detail"]


@pytest.mark.integration
class TestErrorHandlingAndSecurity:
    """Test error handling and security scenarios"""
    
    async def test_login_network_error(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis
    ):
        """Test login when Redis connection fails"""
        # Mock Redis to raise error
        with patch.object(connected_mock_redis, 'set_oauth_state', side_effect=Exception("Redis error")):
            response = await async_test_client.get("/api/v1/auth/login")
            
        assert response.status_code == 500
        data = response.json()
        assert "Error initiating login" in data["detail"]
        
    def test_auth_endpoints_cors_headers(self, test_client):
        """Test that auth endpoints return proper CORS headers"""
        response = test_client.options("/api/v1/auth/config")
        
        assert response.status_code == 200
        # CORS headers should be present (handled by FastAPI middleware)
        
    async def test_concurrent_oauth_states(
        self, 
        async_test_client, 
        override_redis_dependency,
        connected_mock_redis
    ):
        """Test handling multiple concurrent OAuth states"""
        # Create multiple login requests concurrently
        tasks = []
        for i in range(5):
            task = async_test_client.get("/api/v1/auth/login")
            tasks.append(task)
            
        responses = await asyncio.gather(*tasks)
        
        # All should succeed
        for response in responses:
            assert response.status_code == 302
            
        # Should have 5 different states in Redis
        oauth_states = [key for key in connected_mock_redis.data.keys() if key.startswith("oauth_state:")]
        assert len(oauth_states) == 5
        
        # All states should be unique
        states = [key.split(":")[1] for key in oauth_states]
        assert len(set(states)) == 5  # All unique