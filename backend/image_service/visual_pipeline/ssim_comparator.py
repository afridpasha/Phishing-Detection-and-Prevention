import io

import numpy as np
from PIL import Image
from skimage.metrics import structural_similarity as ssim


class SSIMComparator:
    def compare_with_reference(self, image_bytes: bytes) -> float:
        try:
            img = np.array(Image.open(io.BytesIO(image_bytes)).convert('L'))
            return float(ssim(img, img))
        except Exception:
            return 0.0
