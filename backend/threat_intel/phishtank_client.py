import hashlib

import httpx


class PhishTankClient:
    async def lookup(self, url: str) -> dict:
        try:
            sha = hashlib.sha256(url.encode('utf-8')).hexdigest()
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(f'https://checkurl.phishtank.com/checkurl/{sha}')
                if resp.status_code >= 400:
                    return {'in_phishtank': False, 'score': 0.0}
            return {'in_phishtank': False, 'score': 0.0}
        except Exception:
            return {'in_phishtank': False, 'score': 0.0}
