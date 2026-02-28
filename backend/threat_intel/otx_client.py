import httpx

from backend.api_gateway.config import settings


class OTXClient:
    async def lookup_url(self, value: str) -> dict:
        if not settings.OTX_API_KEY:
            return {'in_otx': False, 'score': 0.0}
        try:
            headers = {'X-OTX-API-KEY': settings.OTX_API_KEY}
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(f'https://otx.alienvault.com/api/v1/indicators/url/{value}/general', headers=headers)
                if resp.status_code == 404:
                    return {'in_otx': False, 'score': 0.0}
                resp.raise_for_status()
                data = resp.json()
            pulses = data.get('pulse_info', {}).get('count', 0)
            return {'in_otx': pulses > 0, 'score': min(1.0, pulses / 10.0)}
        except Exception:
            return {'in_otx': False, 'score': 0.0}
