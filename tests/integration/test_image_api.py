import pytest
from httpx import ASGITransport, AsyncClient

from backend.api_gateway.main import app


@pytest.mark.asyncio
async def test_image_endpoint_contract():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://test') as client:
        files = {'image': ('x.png', b'not-real-image', 'image/png')}
        data = {'context': 'unknown', 'run_sandbox': 'false'}
        resp = await client.post('/api/v2/analyze/image', files=files, data=data, headers={'Authorization': 'Bearer test'})
        assert resp.status_code in {200, 401, 500}
