"""
Pytest configuration and fixtures for Finance Tracker tests

Provides:
1. Mock Redis client for unit tests
2. Mock Keycloak responses  
3. Test JWT tokens and users
4. FastAPI test client
5. Database and Redis cleanup
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import json
from typing import Dict, Any, Optional

import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
from jose import jwt

# Import app components with error handling
try:
    from app.main import app
    from app.core.config import settings
    from app.core.redis_client import RedisClient
    APP_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import app modules: {e}")
    print("Creating minimal test configuration...")
    APP_AVAILABLE = False
    
    # Create minimal mock app for testing
    from fastapi import FastAPI
    app = FastAPI(title="Test App")
    
    # Create minimal mock settings
    class MockSettings:
        project_name = "Test Finance Tracker"
        debug = True
        secret_key = "test_secret_key_for_testing_only"
        api_v1_prefix = "/api/v1"
        keycloak_url = "http://localhost:8080"
        keycloak_realm = "finance-realm"
        keycloak_client_id = "finance-tracker"
        keycloak_client_secret = None
        jwt_algorithm = "RS256"
        
    settings = MockSettings()


# === PYTEST CONFIGURATION ===

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests (fast)"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (slow)"
    )
    config.addinivalue_line(
        "markers", "redis: marks tests that require Redis"
    )
    config.addinivalue_line(
        "markers", "keycloak: marks tests that require Keycloak"
    )


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# === MOCK REDIS CLIENT ===

class MockRedisClient:
    """Mock Redis client for testing"""
    
    def __init__(self):
        self.data = {}
        self.counters = {}
        self.connected = False
        
    async def connect(self):
        self.connected = True
        
    async def disconnect(self):
        self.connected = False
        
    async def health_check(self):
        return self.connected
    
    # OAuth state methods
    async def set_oauth_state(self, state: str, data: Dict[str, Any]):
        self.data[f"oauth_state:{state}"] = {
            "data": json.dumps(data),
            "expires_at": datetime.utcnow() + timedelta(seconds=600)
        }
        
    async def get_oauth_state(self, state: str) -> Optional[Dict[str, Any]]:
        key = f"oauth_state:{state}"
        if key in self.data:
            entry = self.data.pop(key)  # One-time use
            if datetime.utcnow() < entry["expires_at"]:
                return json.loads(entry["data"])
        return None
    
    # JWKS caching methods
    async def set_keycloak_jwks(self, jwks: Dict[str, Any]):
        self.data["keycloak:jwks"] = {
            "data": json.dumps(jwks),
            "expires_at": datetime.utcnow() + timedelta(seconds=3600)
        }
        
    async def get_keycloak_jwks(self) -> Optional[Dict[str, Any]]:
        if "keycloak:jwks" in self.data:
            entry = self.data["keycloak:jwks"]
            if datetime.utcnow() < entry["expires_at"]:
                return json.loads(entry["data"])
            else:
                del self.data["keycloak:jwks"]
        return None
    
    # Token blacklist methods
    async def blacklist_token(self, token_jti: str, expires_at: datetime):
        self.data[f"blacklist:{token_jti}"] = {
            "blacklisted_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at
        }
        
    async def is_token_blacklisted(self, token_jti: str) -> bool:
        key = f"blacklist:{token_jti}"
        if key in self.data:
            entry = self.data[key]
            if datetime.utcnow() < entry["expires_at"]:
                return True
            else:
                del self.data[key]
        return False
    
    # Refresh token methods
    async def store_refresh_token(self, token_jti: str, user_id: str, session_data: Dict[str, Any]):
        self.data[f"refresh_token:{token_jti}"] = {
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "last_used": datetime.utcnow().isoformat(),
            **session_data,
            "expires_at": datetime.utcnow() + timedelta(seconds=2592000)  # 30 days
        }
        
    async def get_refresh_token(self, token_jti: str) -> Optional[Dict[str, Any]]:
        key = f"refresh_token:{token_jti}"
        if key in self.data:
            entry = self.data[key]
            if datetime.utcnow() < entry["expires_at"]:
                return entry
            else:
                del self.data[key]
        return None
    
    async def update_refresh_token_usage(self, token_jti: str):
        key = f"refresh_token:{token_jti}"
        if key in self.data:
            self.data[key]["last_used"] = datetime.utcnow().isoformat()
            
    async def revoke_refresh_token(self, token_jti: str):
        key = f"refresh_token:{token_jti}"
        if key in self.data:
            del self.data[key]
            
    async def revoke_all_user_tokens(self, user_id: str) -> int:
        revoked_count = 0
        keys_to_delete = []
        
        for key, data in self.data.items():
            if key.startswith("refresh_token:") and data.get("user_id") == user_id:
                keys_to_delete.append(key)
                revoked_count += 1
                
        for key in keys_to_delete:
            del self.data[key]
            
        return revoked_count
    
    async def get_user_sessions(self, user_id: str):
        sessions = []
        for key, data in self.data.items():
            if key.startswith("refresh_token:") and data.get("user_id") == user_id:
                if datetime.utcnow() < data["expires_at"]:
                    sessions.append(data)
        return sessions
    
    # General caching methods
    async def set_cache(self, key: str, value: Any, ttl: int = 3600):
        self.data[key] = {
            "data": value if isinstance(value, str) else json.dumps(value),
            "expires_at": datetime.utcnow() + timedelta(seconds=ttl)
        }
        
    async def get_cache(self, key: str) -> Optional[str]:
        if key in self.data:
            entry = self.data[key]
            if datetime.utcnow() < entry["expires_at"]:
                return entry["data"]
            else:
                del self.data[key]
        return None
    
    async def delete_cache(self, key: str) -> bool:
        if key in self.data:
            del self.data[key]
            return True
        return False
    
    # Counter methods
    async def increment_counter(self, key: str, ttl: int = 86400) -> int:
        if key not in self.counters:
            self.counters[key] = 0
        self.counters[key] += 1
        return self.counters[key]
    
    async def get_stats(self) -> Dict[str, Any]:
        oauth_states = sum(1 for k in self.data.keys() if k.startswith("oauth_state:"))
        refresh_tokens = sum(1 for k in self.data.keys() if k.startswith("refresh_token:"))
        blacklisted = sum(1 for k in self.data.keys() if k.startswith("blacklist:"))
        
        return {
            "redis_version": "7.0.0-mock",
            "connected_clients": 1,
            "used_memory_human": "1MB",
            "total_commands_processed": 100,
            "oauth_states": oauth_states,
            "refresh_tokens": refresh_tokens,
            "blacklisted_tokens": blacklisted,
            "jwks_cached": "keycloak:jwks" in self.data,
        }


@pytest.fixture
async def mock_redis():
    """Mock Redis client for testing"""
    return MockRedisClient()


@pytest.fixture
async def connected_mock_redis(mock_redis):
    """Connected mock Redis client"""
    await mock_redis.connect()
    yield mock_redis
    await mock_redis.disconnect()


# === TEST JWT TOKENS ===

@pytest.fixture
def test_private_key():
    """Test RSA private key for JWT signing"""
    return """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB
xdKPFO+3LiHBSdthX71CWCV9fy4F/ir5lf+LJvN6JnZOZIiJCmyT4jjzLY8kX0D8
5eVVNI8S/yIBgqeWtxJkWmOGBRlgCOx5qQFCKpR/x7yIFyTDRAGrpDbZlnYvlR0J
qLlf3jgaJsGCk3lJ8P+XhOHzZJ3y1YN4r6SZ2t2/Ov7RYgN9T7U5aJJ5XVNJlQMU
ysD9mSR7bKLnV9aVqK5J+SZqSv9JSNcHFn8QgT8oKQNLdG7mEeTe9N1K6nV7YE1k
xJ4AKHBmCGAjlWZKVJNs6lJ5WDNVQ+yoJyh9aQSL0LK7+3s7nJ7QN/Lt2Kv8xHNl
J6pNqM8LAgMBAAECggEAPDZcqL6z4V+7dLlcfGFgE6Dt+0qJ8VLx4fY8x8WzJ9M=
-----END PRIVATE KEY-----"""


@pytest.fixture
def test_public_key():
    """Test RSA public key for JWT verification"""
    return """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L7VLPHCgcXSjxTv
ty4hwUnbYV+9QlglfX8uBf4q+ZX/iybzeiZ2TmSIiQpsk+I48y2PJF9A/OXlVTSP
Ev8iAYKnlrcSZFpjhgUZYAjseakBQiqUf8e8iBckw0QBq6Q22ZZ2L5UdCai5X944
GibBgpN5SfD/l4Th82Sd8tWDeK+kmdrdt+0i7j7k2R3kJ9Q0qwYJpqaR8JdJfvND
TE7nNdTq15P3LyfAhpT8QYsA6RJfCOaOE7i+9gDxz3r+HMIKt15MJWqB2i1d6KUH
Ln5tkRgWjCDFxtj8VN8Cp7DlTqrGl5MkEyYwLdGJqGPJ3tQKsLhTfDpUJ8qbL9sw
iwIDAQAB
-----END PUBLIC KEY-----"""


@pytest.fixture
def test_user_data():
    """Test user data for JWT tokens"""
    return {
        "sub": "123e4567-e89b-12d3-a456-426614174000",
        "preferred_username": "testuser",
        "email": "testuser@example.com", 
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "realm_access": {
            "roles": ["user", "manager"]
        },
        "resource_access": {
            settings.keycloak_client_id: {
                "roles": ["finance_user"]
            }
        },
        "groups": ["/finance_team"],
        "sid": "session_123",
        "jti": "token_123",
        "iss": f"{settings.keycloak_url}/realms/{settings.keycloak_realm}",
        "aud": settings.keycloak_client_id,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
    }


@pytest.fixture
def test_jwt_token(test_private_key, test_user_data):
    """Create a test JWT token"""
    return jwt.encode(test_user_data, test_private_key, algorithm="RS256")


@pytest.fixture
def expired_jwt_token(test_private_key, test_user_data):
    """Create an expired JWT token"""
    expired_data = test_user_data.copy()
    expired_data["exp"] = int((datetime.utcnow() - timedelta(hours=1)).timestamp())
    return jwt.encode(expired_data, test_private_key, algorithm="RS256")


@pytest.fixture
def test_refresh_token_data(test_user_data):
    """Test refresh token data"""
    return {
        **test_user_data,
        "jti": "refresh_token_123",
        "typ": "Refresh",
        "exp": int((datetime.utcnow() + timedelta(days=30)).timestamp()),
    }


@pytest.fixture  
def test_refresh_token(test_private_key, test_refresh_token_data):
    """Create a test refresh token"""
    return jwt.encode(test_refresh_token_data, test_private_key, algorithm="RS256")


# === MOCK KEYCLOAK RESPONSES ===

@pytest.fixture
def mock_keycloak_jwks():
    """Mock Keycloak JWKS response"""
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-id",
                "n": "u1SU1L7VLPHCgcXSjxTvty4hwUnbYV-9QlglfX8uBf4q-ZX_iybzeiZ2TmSIiQpsk-I48y2PJF9A_OXlVTSPEv8iAYKnlrcSZFpjhgUZYAjseakBQiqUf8e8iBckw0QBq6Q22ZZ2L5UdCai5X944GibBgpN5SfD_l4Th82Sd8tWDeK-kmdrdt-0i7j7k2R3kJ9Q0qwYJpqaR8JdJfvNDTE7nNdTq15P3LyfAhpT8QYsA6RJfCOaOE7i-9gDxz3r-HMIKt15MJWqB2i1d6KUHLn5tkRgWjCDFxtj8VN8Cp7DlTqrGl5MkEyYwLdGJqGPJ3tQKsLhTfDpUJ8qbL9swivA",
                "e": "AQAB"
            }
        ]
    }


@pytest.fixture
def mock_keycloak_token_response():
    """Mock Keycloak token response"""
    return {
        "access_token": "mock_access_token",
        "expires_in": 3600,
        "refresh_expires_in": 2592000,
        "refresh_token": "mock_refresh_token", 
        "token_type": "Bearer",
        "not_before_policy": 0,
        "session_state": "session_123",
        "scope": "openid profile email"
    }


# === FASTAPI TEST CLIENT ===

@pytest.fixture
def test_client():
    """FastAPI test client"""
    return TestClient(app)


@pytest.fixture
async def async_test_client():
    """Async FastAPI test client"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


# === DEPENDENCY OVERRIDES ===

@pytest.fixture
def override_redis_dependency(connected_mock_redis):
    """Override Redis dependency with mock"""
    if not APP_AVAILABLE:
        # If app is not available, skip dependency override
        yield
        return
        
    try:
        from app.core.redis_client import get_redis
        
        async def get_mock_redis():
            return connected_mock_redis
        
        app.dependency_overrides[get_redis] = get_mock_redis
        yield
        app.dependency_overrides.clear()
    except ImportError:
        # If redis_client module is not available, skip override
        yield


# === HTTP MOCKS ===

@pytest.fixture
def mock_httpx_keycloak(mock_keycloak_jwks, mock_keycloak_token_response):
    """Mock httpx calls to Keycloak"""
    
    async def mock_get(url, **kwargs):
        mock_response = AsyncMock()
        if "certs" in url:
            mock_response.json.return_value = mock_keycloak_jwks
            mock_response.raise_for_status.return_value = None
        return mock_response
    
    async def mock_post(url, **kwargs):
        mock_response = AsyncMock()
        if "token" in url:
            data = kwargs.get("data", {})
            if data.get("grant_type") == "authorization_code":
                mock_response.json.return_value = mock_keycloak_token_response
            elif data.get("grant_type") == "refresh_token":
                mock_response.json.return_value = {
                    "access_token": "new_mock_access_token",
                    "expires_in": 3600,
                    "refresh_token": "new_mock_refresh_token",
                    "token_type": "Bearer"
                }
            else:
                mock_response.status_code = 400
                mock_response.raise_for_status.side_effect = Exception("Invalid grant type")
        mock_response.raise_for_status.return_value = None
        return mock_response
    
    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get = mock_get
        mock_instance.post = mock_post
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.__aexit__.return_value = None
        mock_client.return_value = mock_instance
        yield mock_instance


# === TEST CLEANUP ===

@pytest.fixture(autouse=True)
async def cleanup_after_test():
    """Cleanup after each test"""
    yield
    # Clear any cached data
    if hasattr(app.state, "redis"):
        try:
            await app.state.redis.disconnect()
        except:
            pass


# === PARAMETRIZED FIXTURES ===

@pytest.fixture(params=["user", "manager", "admin"])
def user_role(request):
    """Parametrized user roles for testing"""
    return request.param


@pytest.fixture(params=[
    {"grant_type": "authorization_code", "code": "test_code"},
    {"grant_type": "refresh_token", "refresh_token": "test_refresh"},
])
def token_request_data(request):
    """Parametrized token request data"""
    return request.param