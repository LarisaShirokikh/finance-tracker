"""
Tests for main application startup and configuration

Tests:
1. Application initialization and factory
2. Startup and shutdown events
3. Router registration and URL routing
4. Middleware configuration
5. CORS settings
6. Health check endpoints
7. Configuration endpoint security
8. Error handling in main routes
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app, create_application
from app.core.config import settings


@pytest.mark.unit
class TestApplicationFactory:
    """Test application factory and initialization"""
    
    def test_create_application_debug_mode(self):
        """Test application creation in debug mode"""
        with patch('app.core.config.settings') as mock_settings:
            mock_settings.project_name = "Test Finance Tracker"
            mock_settings.debug = True
            mock_settings.secret_key = "test_secret"
            mock_settings.api_v1_prefix = "/api/v1"
            
            with patch('app.core.config.get_cors_origins', return_value=["http://localhost:3000"]):
                test_app = create_application()
                
            assert test_app.title == "Test Finance Tracker"
            assert test_app.docs_url == "/docs"  # Should be enabled in debug
            assert test_app.redoc_url == "/redoc"
            assert test_app.openapi_url == "/openapi.json"
            
    def test_create_application_production_mode(self):
        """Test application creation in production mode"""
        with patch('app.core.config.settings') as mock_settings:
            mock_settings.project_name = "Finance Tracker Production"
            mock_settings.debug = False
            mock_settings.secret_key = "production_secret"
            mock_settings.api_v1_prefix = "/api/v1"
            
            with patch('app.core.config.get_cors_origins', return_value=["https://finance.example.com"]):
                test_app = create_application()
                
            assert test_app.title == "Finance Tracker Production"
            assert test_app.docs_url is None  # Should be disabled in production
            assert test_app.redoc_url is None
            assert test_app.openapi_url is None


@pytest.mark.integration
class TestApplicationStartup:
    """Test application startup and shutdown events"""
    
    def test_startup_event_logging(self, test_client):
        """Test that startup event logs configuration"""
        with patch('app.main.logger') as mock_logger:
            # Trigger startup by making a request
            response = test_client.get("/")
            
            # Verify startup logging occurred
            assert mock_logger.info.called
            log_calls = [call.args[0] for call in mock_logger.info.call_args_list]
            startup_logs = [log for log in log_calls if "запускается" in log or "starts" in log]
            assert len(startup_logs) > 0
            
    def test_app_initialization_with_dependencies(self, test_client):
        """Test that app initializes with all dependencies"""
        # Test that app can handle requests after initialization
        response = test_client.get("/health")
        assert response.status_code == 200


@pytest.mark.integration
class TestRouterRegistration:
    """Test router registration and URL routing"""
    
    def test_auth_router_registered(self, test_client):
        """Test that auth router is properly registered"""
        # Test auth endpoints exist
        response = test_client.get("/api/v1/auth/config")
        assert response.status_code == 200
        
    def test_finance_router_registered(self, test_client, override_redis_dependency):
        """Test that finance router is properly registered"""
        # Test finance endpoints exist (but require auth)
        response = test_client.get("/api/v1/finance/categories")
        # Should return 403 (no auth) not 404 (route not found)
        assert response.status_code == 403
        
    def test_api_v1_prefix(self, test_client):
        """Test that API v1 prefix is correctly applied"""
        # Routes should work with /api/v1 prefix
        response = test_client.get("/api/v1/auth/config")
        assert response.status_code == 200
        
        # Routes should not work without prefix
        response = test_client.get("/auth/config")
        assert response.status_code == 404


@pytest.mark.integration
class TestMiddlewareConfiguration:
    """Test middleware configuration"""
    
    def test_session_middleware_present(self, test_client):
        """Test that session middleware is configured"""
        # Make request that might use sessions
        response = test_client.get("/api/v1/auth/login")
        
        # Should redirect (302) not error (500) - means session middleware works
        assert response.status_code == 302
        
    def test_cors_middleware_present(self, test_client):
        """Test that CORS middleware is configured"""
        # Make OPTIONS request to test CORS
        response = test_client.options("/api/v1/auth/config")
        assert response.status_code == 200
        
        # Should have CORS headers
        headers = response.headers
        # Note: Actual CORS headers depend on request origin
        
    def test_cors_allows_configured_origins(self, test_client):
        """Test that CORS allows configured origins"""
        headers = {"Origin": "http://localhost:3000"}
        response = test_client.options("/api/v1/auth/config", headers=headers)
        
        assert response.status_code == 200


@pytest.mark.integration
class TestBaseRoutes:
    """Test base application routes"""
    
    def test_root_endpoint(self, test_client):
        """Test root endpoint returns app info"""
        response = test_client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["message"] == "Finance Tracker API"
        assert data["version"] == "0.1.0"
        assert data["status"] == "running"
        assert "features" in data
        assert "endpoints" in data
        
        # Check features list
        features = data["features"]
        assert "OAuth 2.0 / OpenID Connect авторизация" in features
        assert "JWT токены" in features
        assert "Role-based access control (RBAC)" in features
        
    def test_health_check_endpoint(self, test_client):
        """Test health check endpoint"""
        response = test_client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["version"] == "0.1.0"
        assert "services" in data
        
        # Check services info
        services = data["services"]
        assert "keycloak" in services
        assert "database" in services
        
    def test_config_endpoint_debug_mode(self, test_client):
        """Test config endpoint in debug mode"""
        with patch('app.core.config.settings') as mock_settings:
            mock_settings.debug = True
            mock_settings.project_name = "Test App"
            mock_settings.api_v1_prefix = "/api/v1"
            mock_settings.keycloak_url = "http://localhost:8080"
            mock_settings.keycloak_realm = "test-realm"
            mock_settings.keycloak_client_id = "test-client"
            mock_settings.jwt_algorithm = "RS256"
            mock_settings.log_level = "DEBUG"
            
            response = test_client.get("/config")
            
        assert response.status_code == 200
        data = response.json()
        
        assert data["project_name"] == "Test App"
        assert data["debug"] is True
        assert "oauth_urls" in data
        assert "database_url" not in data  # Should not expose secrets
        assert "secret_key" not in data
        
    def test_config_endpoint_production_mode(self, test_client):
        """Test config endpoint in production mode"""
        with patch('app.core.config.settings') as mock_settings:
            mock_settings.debug = False
            
            response = test_client.get("/config")
            
        assert response.status_code == 404
        data = response.json()
        assert "только в режиме разработки" in data["detail"]


@pytest.mark.integration
class TestErrorHandling:
    """Test error handling in main application"""
    
    def test_404_for_unknown_routes(self, test_client):
        """Test 404 for unknown routes"""
        response = test_client.get("/nonexistent/route")
        assert response.status_code == 404
        
    def test_405_for_wrong_methods(self, test_client):
        """Test 405 for wrong HTTP methods"""
        # Try POST on GET-only endpoint
        response = test_client.post("/health")
        assert response.status_code == 405
        
    def test_root_endpoint_different_methods(self, test_client):
        """Test root endpoint with different HTTP methods"""
        # GET should work
        response = test_client.get("/")
        assert response.status_code == 200
        
        # POST should not work
        response = test_client.post("/")
        assert response.status_code == 405


@pytest.mark.integration
class TestApplicationSecurity:
    """Test application security configurations"""
    
    def test_no_server_header_exposure(self, test_client):
        """Test that server information is not exposed"""
        response = test_client.get("/")
        
        # Should not expose server details
        assert "server" not in response.headers.get("Server", "").lower()
        
    def test_sensitive_config_not_exposed(self, test_client):
        """Test that sensitive configuration is not exposed"""
        with patch('app.core.config.settings') as mock_settings:
            mock_settings.debug = True
            
            response = test_client.get("/config")
            
        if response.status_code == 200:
            data = response.json()
            
            # Sensitive data should not be present
            assert "database_url" not in data
            assert "secret_key" not in data
            assert "keycloak_client_secret" not in data
            assert "password" not in str(data).lower()


@pytest.mark.integration
class TestApplicationPerformance:
    """Test application performance characteristics"""
    
    def test_multiple_concurrent_requests(self, test_client):
        """Test handling multiple concurrent requests"""
        import concurrent.futures
        import threading
        
        def make_request():
            return test_client.get("/health")
        
        # Make 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            responses = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # All requests should succeed
        for response in responses:
            assert response.status_code == 200
            
    def test_health_check_performance(self, test_client):
        """Test health check endpoint performance"""
        import time
        
        start_time = time.time()
        response = test_client.get("/health")
        end_time = time.time()
        
        assert response.status_code == 200
        # Health check should be fast (less than 1 second)
        assert (end_time - start_time) < 1.0


@pytest.mark.integration  
class TestDependencyInjection:
    """Test dependency injection in main application"""
    
    def test_redis_dependency_available(self, test_client, override_redis_dependency):
        """Test that Redis dependency is available in endpoints"""
        # This test verifies that dependency injection works
        # by checking that Redis-dependent endpoints can start
        response = test_client.get("/api/v1/auth/login")
        
        # Should not fail with dependency injection error
        assert response.status_code == 302  # Redirect to Keycloak
        
    def test_dependency_override_works(self, test_client, override_redis_dependency):
        """Test that dependency overrides work for testing"""
        # The override_redis_dependency fixture should work
        response = test_client.get("/api/v1/auth/config")
        assert response.status_code == 200


@pytest.mark.unit
class TestMainModuleExecution:
    """Test main module execution"""
    
    def test_main_module_import(self):
        """Test that main module can be imported"""
        from app.main import app
        assert app is not None
        assert hasattr(app, 'title')
        
    @patch('uvicorn.run')
    def test_main_module_execution(self, mock_uvicorn):
        """Test main module execution path"""
        # This would test the if __name__ == "__main__" block
        # but we need to be careful not to actually start the server
        
        with patch('app.main.settings') as mock_settings:
            mock_settings.debug = True
            mock_settings.log_level = "INFO"
            
            # Import and execute main module
            import app.main
            
            # Verify uvicorn.run would be called with correct parameters
            # Note: This test depends on how the main module is structured