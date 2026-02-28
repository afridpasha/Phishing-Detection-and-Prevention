import io

import numpy as np
from PIL import Image


class EfficientNetScorer:
    def score(self, image_bytes: bytes) -> float:
        try:
            arr = np.array(Image.open(io.BytesIO(image_bytes)).convert('RGB'), dtype=np.float32)
            contrast = arr.std() / 255.0
            return float(max(0.0, min(1.0, 0.3 + contrast)))
        except Exception:
            return 0.0
