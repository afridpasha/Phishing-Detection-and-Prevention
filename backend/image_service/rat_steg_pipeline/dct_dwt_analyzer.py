import numpy as np
from PIL import Image
try:
    import pywt
except Exception:  # pragma: no cover
    pywt = None
try:
    from scipy.fftpack import dct
except Exception:  # pragma: no cover
    dct = None


class DCTDWTAnalyzer:
    def analyze(self, image_bytes: bytes) -> dict:
        try:
            if pywt is None or dct is None:
                return {'dct_steg_score': 0.0, 'dwt_noise_ratio': 0.0, 'dct_dwt_suspicious': False}
            import io
            arr = np.array(Image.open(io.BytesIO(image_bytes)).convert('L'), dtype=np.float32)
            h, w = arr.shape
            h8, w8 = h - (h % 8), w - (w % 8)
            arr = arr[:h8, :w8]

            dct_scores = []
            for i in range(0, h8, 8):
                for j in range(0, w8, 8):
                    block = arr[i:i+8, j:j+8]
                    coeff = dct(dct(block.T, norm='ortho').T, norm='ortho')
                    flat = np.abs(coeff).flatten()[1:]
                    if flat.size:
                        dct_scores.append(np.mean((flat % 2) < 0.2))

            cA, (cH, cV, cD) = pywt.dwt2(arr, 'haar')
            dwt_noise_ratio = float(np.mean(np.abs(cH)) + np.mean(np.abs(cV)) + np.mean(np.abs(cD))) / (float(np.mean(np.abs(cA))) + 1e-6)
            dct_score = float(np.mean(dct_scores)) if dct_scores else 0.0
            suspicious = dct_score > 0.65 or dwt_noise_ratio > 1.2
            return {'dct_steg_score': dct_score, 'dwt_noise_ratio': dwt_noise_ratio, 'dct_dwt_suspicious': suspicious}
        except Exception as exc:
            return {'dct_steg_score': 0.0, 'dwt_noise_ratio': 0.0, 'dct_dwt_suspicious': False, 'error': str(exc)}
