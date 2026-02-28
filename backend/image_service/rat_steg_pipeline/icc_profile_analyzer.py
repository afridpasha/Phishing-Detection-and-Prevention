import io

from PIL import Image


class ICCProfileAnalyzer:
    def analyze(self, image_bytes: bytes) -> dict:
        try:
            img = Image.open(io.BytesIO(image_bytes))
            icc = img.info.get('icc_profile')
            if not icc:
                return {'icc_profile_present': False, 'icc_suspicious': False, 'icc_profile_size': 0}
            icc_size = len(icc)
            suspicious = icc_size > 250000 or b'javascript' in icc.lower() or b'<script' in icc.lower()
            return {'icc_profile_present': True, 'icc_suspicious': bool(suspicious), 'icc_profile_size': icc_size}
        except Exception:
            return {'icc_profile_present': False, 'icc_suspicious': False, 'icc_profile_size': 0}
