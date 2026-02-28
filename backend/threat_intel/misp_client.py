import httpx

from backend.api_gateway.config import settings


class MISPClient:
    async def lookup(self, value: str) -> dict:
        if not settings.MISP_URL or not settings.MISP_API_KEY:
            return {'in_misp': False, 'score': 0.0}
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(
                    f"{settings.MISP_URL.rstrip('/')}/attributes/restSearch",
                    headers={'Authorization': settings.MISP_API_KEY, 'Accept': 'application/json'},
                    json={'value': value},
                )
                resp.raise_for_status()
                data = resp.json()
            attrs = data.get('response', {}).get('Attribute', []) if isinstance(data, dict) else []
            return {'in_misp': bool(attrs), 'score': 0.8 if attrs else 0.0}
        except Exception:
            return {'in_misp': False, 'score': 0.0}
