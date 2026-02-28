try:
    import cv2
except Exception:  # pragma: no cover
    cv2 = None
import numpy as np


class QRDecoder:
    def __init__(self):
        self._reader = None
        try:
            import pyzxing
            self._reader = pyzxing.BarCodeReader()
        except Exception:
            self._reader = None

    def decode_qr_array(self, img_array: np.ndarray) -> dict:
        if self._reader:
            try:
                results = self._reader.decode_array(img_array)
                if results:
                    row = results[0]
                    return {'content': row.get('raw', ''), 'format': row.get('format', '')}
            except Exception:
                pass
        if cv2 is None:
            return {'content': '', 'format': ''}
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img_array)
        return {'content': data or '', 'format': 'QR_CODE' if data else ''}
