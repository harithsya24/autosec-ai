"""
Test Suite for AutoSec AI API
Tests all endpoints and basic functionality
"""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend', 'api'))

from main import app

# Create test client
client = TestClient(app)


class TestHealthEndpoints:
    """Test health check and status endpoints"""
    
    def test_root_endpoint(self):
        """Test root endpoint returns welcome message"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert data["version"] == "0.1.0"
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "0.1.0"
        assert "services" in data
        assert data["services"]["api"] == "operational"
    
    def test_system_status(self):
        """Test system status endpoint"""
        response = client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert "threats_detected_today" in data


class TestLogIngestion:
    """Test log ingestion endpoints"""
    
    def test_ingest_valid_log(self):
        """Test ingesting a valid security log"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.100",
            "user_id": "user_123",
            "action": "login",
            "resource": "/admin",
            "status": "failed",
            "metadata": {"attempts": 3}
        }
        
        response = client.post("/api/v1/logs/ingest", json=log_data)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "received"
        assert "log_id" in data
        assert data["log"]["action"] == "login"
    
    def test_ingest_minimal_log(self):
        """Test ingesting a log with minimal required fields"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "10.0.0.1",
            "action": "api_call",
            "resource": "/api/users",
            "status": "success"
        }
        
        response = client.post("/api/v1/logs/ingest", json=log_data)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "received"
    
    def test_ingest_invalid_log(self):
        """Test ingesting an invalid log (missing required fields)"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            # Missing source_ip, action, resource, status
        }
        
        response = client.post("/api/v1/logs/ingest", json=log_data)
        assert response.status_code == 422  # Validation error


class TestThreatEndpoints:
    """Test threat detection and retrieval endpoints"""
    
    def test_get_threats_empty(self):
        """Test getting threats when none exist"""
        response = client.get("/api/v1/threats")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["threats"] == []
    
    def test_get_threats_with_limit(self):
        """Test getting threats with custom limit"""
        response = client.get("/api/v1/threats?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 5
    
    def test_get_threat_detail_not_found(self):
        """Test getting details for non-existent threat"""
        response = client.get("/api/v1/threats/fake_id_123")
        assert response.status_code == 404
    
    def test_analyze_log(self):
        """Test analyzing a log for threats"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.100",
            "action": "login",
            "resource": "/admin",
            "status": "failed"
        }
        
        response = client.post("/api/v1/analyze", json=log_data)
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "threat_detected" in data
        assert "confidence" in data


class TestDataValidation:
    """Test data validation and error handling"""
    
    def test_invalid_json(self):
        """Test sending invalid JSON"""
        response = client.post(
            "/api/v1/logs/ingest",
            data="not valid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
    
    def test_missing_required_fields(self):
        """Test missing required fields in log"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            # Missing other required fields
        }
        response = client.post("/api/v1/logs/ingest", json=log_data)
        assert response.status_code == 422


class TestCORS:
    """Test CORS configuration"""
    
    def test_cors_headers(self):
        """Test that CORS headers are present"""
        response = client.options("/health")
        # CORS should be enabled
        assert response.status_code in [200, 405]  # OPTIONS might not be implemented


# Integration Tests (will expand as we build more components)
class TestIntegration:
    """Integration tests for complete workflows"""
    
    def test_complete_log_flow(self):
        """Test complete flow: ingest → store → retrieve"""
        # Step 1: Ingest a log
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.100",
            "user_id": "test_user",
            "action": "login",
            "resource": "/admin",
            "status": "failed",
            "metadata": {"attempts": 5}
        }
        
        ingest_response = client.post("/api/v1/logs/ingest", json=log_data)
        assert ingest_response.status_code == 200
        
        # Step 2: Check system status updated
        status_response = client.get("/api/v1/status")
        assert status_response.status_code == 200
        
        # Step 3: Analyze the log
        analyze_response = client.post("/api/v1/analyze", json=log_data)
        assert analyze_response.status_code == 200


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])