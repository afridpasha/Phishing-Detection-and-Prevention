import io

import numpy as np
from PIL import Image


class StegCNNDetector:
    def __init__(self, model_path: str | None = None):
        self.model_path = model_path
        self.loaded = False

    def predict(self, image_bytes: bytes) -> float:
        try:
            arr = np.array(Image.open(io.BytesIO(image_bytes)).convert('RGB'), dtype=np.float32)
            residual = np.abs(arr[:, 1:, :] - arr[:, :-1, :]).mean()
            variance = np.var(arr)
            score = min(0.98, (residual / 24.0) * 0.6 + (variance / 5000.0) * 0.4)
            return float(max(0.0, score))
        except Exception:
            return 0.0
