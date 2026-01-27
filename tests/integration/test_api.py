"""
Integration Tests - API Gateway
"""

import pytest
import requests
import time

API_BASE = "http://localhost:8000/api/v1"


class TestAPIIntegration:
    def test_health_endpoint(self):
        response = requests.get("http://localhost:8000/health")
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
    
    def test_email_analysis(self):
        payload = {
            "subject": "URGENT: Your account will be suspended",
            "body": "Click here to verify: http://phishing.tk",
            "sender": "fake@suspicious.com"
        }
        response = requests.post(f"{API_BASE}/analyze/email", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 'final_score' in data
        assert 'action' in data
        assert data['action'] in ['allow', 'warn', 'block']
    
    def test_url_analysis(self):
        payload = {"url": "http://192.168.1.1/admin"}
        response = requests.post(f"{API_BASE}/analyze/url", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data['final_score'] > 0
    
    def test_sms_analysis(self):
        payload = {
            "message": "Your package is waiting. Click: http://bit.ly/abc123",
            "sender": "+1234567890"
        }
        response = requests.post(f"{API_BASE}/analyze/sms", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert 'risk_level' in data
    
    def test_statistics_endpoint(self):
        response = requests.get(f"{API_BASE}/statistics")
        assert response.status_code == 200
        data = response.json()
        assert 'total_requests' in data
    
    def test_response_time(self):
        payload = {"url": "https://google.com"}
        start = time.time()
        response = requests.post(f"{API_BASE}/analyze/url", json=payload)
        latency = (time.time() - start) * 1000
        assert response.status_code == 200
        assert latency < 200  # Should be under 200ms


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
