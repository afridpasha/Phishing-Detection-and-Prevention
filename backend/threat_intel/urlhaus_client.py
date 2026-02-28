import httpx


class URLHausClient:
    async def lookup(self, url: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post('https://urlhaus-api.abuse.ch/v1/url/', data={'url': url})
                resp.raise_for_status()
                data = resp.json()
            listed = data.get('query_status') == 'ok'
            return {'in_urlhaus': listed, 'score': 0.9 if listed else 0.0}
        except Exception:
            return {'in_urlhaus': False, 'score': 0.0}
