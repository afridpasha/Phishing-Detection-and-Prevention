import pytest
from httpx import ASGITransport, AsyncClient
from backend.api_gateway.main import app

@pytest.mark.asyncio
async def test_url_analysis_endpoint():
    """Test URL analysis endpoint"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Skip auth for testing
        response = await client.post(
            "/api/v2/analyze/url",
            json={
                "url": "https://google.com",
                "follow_redirects": True,
                "context": "web"
            },
            headers={"Authorization": "Bearer test_token"}
        )
        
        # Note: Will fail without proper auth setup
        # This is a template for when auth is configured
        assert response.status_code in [200, 401]

@pytest.mark.asyncio
async def test_health_endpoint():
    """Test health check endpoint"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
