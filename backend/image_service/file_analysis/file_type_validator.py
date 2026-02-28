import os
from typing import Dict

try:
    import magic
except Exception:  # pragma: no cover
    magic = None


class FileTypeValidator:
    def __init__(self):
        self._magic = magic.Magic(mime=True) if magic is not None else None
        self._map = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'bmp': 'image/bmp',
            'svg': 'image/svg+xml',
            'webp': 'image/webp',
        }

    def validate(self, file_bytes: bytes, filename: str | None = None) -> Dict:
        actual = self._magic.from_buffer(file_bytes) if self._magic is not None else 'application/octet-stream'
        ext = (os.path.splitext(filename or '')[-1].lstrip('.').lower() if filename else '')
        expected = self._map.get(ext, actual)
        mismatch = expected != actual
        return {'actual_type': actual, 'expected_type': expected, 'extension': ext, 'mismatch': mismatch}
