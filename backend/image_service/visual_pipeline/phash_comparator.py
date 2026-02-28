import io

import imagehash
from PIL import Image


class PHashComparator:
    def compare(self, image_bytes: bytes) -> dict:
        try:
            img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            phash = str(imagehash.phash(img))
            return {'phash': phash, 'phash_match_confidence': 0.5}
        except Exception:
            return {'phash': '', 'phash_match_confidence': 0.0}
