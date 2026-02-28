import pytest
from httpx import ASGITransport, AsyncClient

from backend.api_gateway.main import app


@pytest.mark.asyncio
async def test_email_endpoint_contract():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://test') as client:
        resp = await client.post(
            '/api/v2/analyze/email',
            json={
                'subject': 'Urgent verify',
                'body_text': 'Click now',
                'sender_email': 'test@example.com'
            },
            headers={'Authorization': 'Bearer test'},
        )
        assert resp.status_code in {200, 401}
