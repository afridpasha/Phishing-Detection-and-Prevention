from typing import List, Tuple

try:
    import cv2
except Exception:  # pragma: no cover
    cv2 = None
import numpy as np
from PIL import Image


class QRDetector:
    def detect(self, image_bytes: bytes) -> List[Tuple[int, int, int, int]]:
        if cv2 is None:
            return []
        try:
            import io
            img = np.array(Image.open(io.BytesIO(image_bytes)).convert('RGB'))
            detector = cv2.QRCodeDetector()
            ok, points = detector.detect(img)
            if not ok or points is None:
                return []
            pts = points.astype(int).reshape(-1, 2)
            x, y = pts[:, 0].min(), pts[:, 1].min()
            w, h = pts[:, 0].max() - x, pts[:, 1].max() - y
            return [(int(x), int(y), int(w), int(h))]
        except Exception:
            return []
