import httpx

from backend.api_gateway.config import settings


class ImageSandboxClient:
    def __init__(self):
        self.base_url = settings.CAPE_URL.rstrip('/')
        self.api_key = settings.CAPE_API_KEY

    async def detonate(self, image_bytes: bytes, filename: str = 'sample.bin') -> dict:
        if not self.api_key:
            return {'sandbox_detonated': False, 'c2_beacons_detected': False, 'c2_domains': []}
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'}
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(f'{self.base_url}/api/tasks/create/file', headers=headers, files={'file': (filename, image_bytes)})
                resp.raise_for_status()
            return {'sandbox_detonated': True, 'c2_beacons_detected': False, 'c2_domains': []}
        except Exception:
            return {'sandbox_detonated': False, 'c2_beacons_detected': False, 'c2_domains': []}
