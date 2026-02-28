import base64
from typing import Dict

import httpx

from backend.api_gateway.config import settings


class CAPEClient:
    def __init__(self):
        self.base_url = settings.CAPE_URL.rstrip('/')
        self.api_key = settings.CAPE_API_KEY

    async def submit_file(self, filename: str, content_b64: str) -> Dict:
        if not self.api_key:
            return {'verdict': 'unknown', 'malware_family': None, 'sandbox_detonated': False}
        try:
            content = base64.b64decode(content_b64)
            headers = {'Authorization': f'Bearer {self.api_key}'}
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(f'{self.base_url}/api/tasks/create/file', headers=headers, files={'file': (filename, content)})
                resp.raise_for_status()
            return {'verdict': 'submitted', 'malware_family': None, 'sandbox_detonated': True}
        except Exception:
            return {'verdict': 'unknown', 'malware_family': None, 'sandbox_detonated': False}
