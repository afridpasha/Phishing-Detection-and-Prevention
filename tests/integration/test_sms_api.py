import pytest
from httpx import ASGITransport, AsyncClient

from backend.api_gateway.main import app


@pytest.mark.asyncio
async def test_sms_endpoint_contract():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://test') as client:
        resp = await client.post(
            '/api/v2/analyze/sms',
            json={'message': 'Verify your bank account now http://x.co', 'language': 'en'},
            headers={'Authorization': 'Bearer test'},
        )
        assert resp.status_code in {200, 401}
