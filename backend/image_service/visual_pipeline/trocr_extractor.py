import io

from PIL import Image


class TrOCRExtractor:
    def __init__(self):
        self._ocr = None
        try:
            import pytesseract
            self._ocr = pytesseract
        except Exception:
            self._ocr = None

    def extract_text(self, image_bytes: bytes) -> str:
        if not self._ocr:
            return ''
        try:
            img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            return self._ocr.image_to_string(img).strip()
        except Exception:
            return ''
