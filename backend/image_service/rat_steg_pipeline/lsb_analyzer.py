import numpy as np
try:
    from scipy.stats import chisquare
except Exception:  # pragma: no cover
    chisquare = None
from PIL import Image
import io

class LSBAnalyzer:
    """Detect LSB steganography using Chi-square and RS analysis"""
    
    def analyze(self, image_bytes: bytes) -> dict:
        """Analyze image for LSB steganography"""
        try:
            img = Image.open(io.BytesIO(image_bytes))
            img_array = np.array(img)
            
            # Chi-square test
            chi_square_result = self._chi_square_test(img_array)
            
            # RS analysis
            rs_ratio = self._rs_analysis(img_array)
            
            # Determine if steganography detected
            steg_detected = chi_square_result['p_value'] < 0.001 or rs_ratio > 1.8
            
            return {
                'steganography_detected': steg_detected,
                'chi_square_pvalue': chi_square_result['p_value'],
                'rs_ratio': rs_ratio,
                'method': 'LSB_spatial' if steg_detected else None,
                'confidence': 0.94 if steg_detected else 0.0
            }
        except Exception as e:
            return {
                'steganography_detected': False,
                'chi_square_pvalue': 1.0,
                'rs_ratio': 1.0,
                'method': None,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _chi_square_test(self, img_array: np.ndarray) -> dict:
        """Perform Chi-square test on LSB plane"""
        if len(img_array.shape) == 3:
            # Use first channel for color images
            channel = img_array[:, :, 0].flatten()
        else:
            channel = img_array.flatten()
        
        # Extract LSB plane
        lsb_plane = channel & 1
        
        # Count pairs of adjacent values
        pairs = []
        for i in range(len(lsb_plane) - 1):
            pairs.append((lsb_plane[i], lsb_plane[i+1]))
        
        # Count occurrences
        pair_counts = {}
        for pair in pairs:
            pair_counts[pair] = pair_counts.get(pair, 0) + 1
        
        observed = list(pair_counts.values())
        expected = [len(pairs) / 4] * len(observed)
        
        if len(observed) > 1:
            if chisquare is None:
                chi2, p_value = 0, 1.0
            else:
                chi2, p_value = chisquare(observed, expected)
        else:
            chi2, p_value = 0, 1.0
        
        return {'chi2': chi2, 'p_value': p_value}
    
    def _rs_analysis(self, img_array: np.ndarray) -> float:
        """Perform RS (Regular-Singular) analysis"""
        if len(img_array.shape) == 3:
            channel = img_array[:, :, 0]
        else:
            channel = img_array

        regular_count = 0
        singular_count = 0

        # Process 2x2 blocks and skip near-constant blocks: they carry little RS signal
        h, w = channel.shape
        for i in range(0, h - 1, 2):
            for j in range(0, w - 1, 2):
                block = channel[i:i + 2, j:j + 2].astype(np.int16)
                if float(np.var(block)) < 1.0:
                    continue

                original_discrimination = self._discrimination(block)
                flipped_discrimination = self._discrimination(self._flip_lsb_masked(block))

                if flipped_discrimination > original_discrimination + 1e-9:
                    regular_count += 1
                elif flipped_discrimination < original_discrimination - 1e-9:
                    singular_count += 1

        if regular_count == 0 and singular_count == 0:
            return 1.0

        return (regular_count + 1.0) / (singular_count + 1.0)

    def _flip_lsb_masked(self, block: np.ndarray) -> np.ndarray:
        """Apply RS mask by toggling LSB on alternating positions in a 2x2 block."""
        flipped = block.copy()
        flat = flipped.reshape(-1)
        for idx in (0, 2):
            flat[idx] ^= 1
        return flipped

    def _discrimination(self, block: np.ndarray) -> float:
        """Local smoothness/discrimination function used by RS analysis."""
        flat = block.reshape(-1).astype(np.float64)
        return float(np.sum(np.abs(np.diff(flat))))
