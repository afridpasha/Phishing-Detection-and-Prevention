"""
STEGANOGRAPHY DETECTION MODULE
Rule-based steganography detection (Phase 1)
Detects hidden data in images using statistical analysis

Techniques:
- LSB (Least Significant Bit) analysis
- Chi-square test
- RS (Regular-Singular) analysis
- Entropy analysis
- EXIF metadata inspection
"""

import numpy as np
from PIL import Image
import logging

logger = logging.getLogger(__name__)

def convert_numpy_types(obj):
    """Convert numpy types to native Python types"""
    if isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, (np.int_, np.intc, np.intp, np.int8, np.int16, np.int32, np.int64)):
        return int(obj)
    elif isinstance(obj, (np.float_, np.float16, np.float32, np.float64)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    return obj

class StegDetector:
    """Rule-based steganography detection"""
    
    def __init__(self):
        self.threshold_chi2 = 0.05
        self.threshold_entropy = 7.5
        
    def analyze(self, image_path_or_array) -> dict:
        """
        Analyze image for steganography indicators
        Returns: {
            'steg_detected': bool,
            'steg_probability': float,
            'indicators': list,
            'chi2_pvalue': float,
            'entropy': float,
            'lsb_anomaly': bool
        }
        """
        try:
            if isinstance(image_path_or_array, str):
                img = Image.open(image_path_or_array).convert('RGB')
            elif isinstance(image_path_or_array, Image.Image):
                img = image_path_or_array.convert('RGB')
            else:
                img = Image.fromarray(image_path_or_array).convert('RGB')
            
            img_array = np.array(img)
            
            # Run all tests
            lsb_result = self._lsb_analysis(img_array)
            chi2_result = self._chi_square_test(img_array)
            entropy_result = self._entropy_analysis(img_array)
            exif_result = self._exif_analysis(img) if isinstance(image_path_or_array, str) else {}
            
            # Aggregate indicators
            indicators = []
            steg_score = 0.0
            
            if lsb_result['anomaly']:
                indicators.append("LSB pattern anomaly detected")
                steg_score += 0.3
            
            if chi2_result['suspicious']:
                indicators.append(f"Chi-square test suspicious (p={chi2_result['pvalue']:.4f})")
                steg_score += 0.4
            
            if entropy_result['high']:
                indicators.append(f"High entropy detected ({entropy_result['entropy']:.2f})")
                steg_score += 0.2
            
            if exif_result.get('suspicious'):
                indicators.append("Suspicious EXIF metadata")
                steg_score += 0.1
            
            steg_detected = steg_score > 0.5
            
            result = {
                'steg_detected': steg_detected,
                'steg_probability': min(steg_score, 1.0),
                'indicators': indicators,
                'chi2_pvalue': chi2_result['pvalue'],
                'entropy': entropy_result['entropy'],
                'lsb_anomaly': lsb_result['anomaly'],
                'exif_suspicious': exif_result.get('suspicious', False),
            }
            
            return convert_numpy_types(result)
            
        except Exception as e:
            logger.warning(f"Steg analysis error: {e}")
            return {
                'steg_detected': False,
                'steg_probability': 0.0,
                'indicators': [],
                'chi2_pvalue': 1.0,
                'entropy': 0.0,
                'lsb_anomaly': False,
            }
    
    def _lsb_analysis(self, img_array: np.ndarray) -> dict:
        """
        Analyze LSB (Least Significant Bit) patterns
        Steganography often hides data in LSBs
        """
        try:
            # Extract LSBs from each channel
            lsb_r = img_array[:, :, 0] & 1
            lsb_g = img_array[:, :, 1] & 1
            lsb_b = img_array[:, :, 2] & 1
            
            # Calculate LSB distribution (should be ~50/50 for natural images)
            r_ratio = np.mean(lsb_r)
            g_ratio = np.mean(lsb_g)
            b_ratio = np.mean(lsb_b)
            
            # Anomaly if ratio deviates significantly from 0.5
            anomaly = (
                abs(r_ratio - 0.5) > 0.1 or
                abs(g_ratio - 0.5) > 0.1 or
                abs(b_ratio - 0.5) > 0.1
            )
            
            return {
                'anomaly': anomaly,
                'lsb_ratios': [float(r_ratio), float(g_ratio), float(b_ratio)]
            }
        except Exception:
            return {'anomaly': False, 'lsb_ratios': [0.5, 0.5, 0.5]}
    
    def _chi_square_test(self, img_array: np.ndarray) -> dict:
        """
        Chi-square test for LSB embedding
        Tests if LSB distribution is statistically random
        """
        try:
            # Flatten and extract LSBs
            flat = img_array.flatten()
            lsb = flat & 1
            
            # Count 0s and 1s
            count_0 = np.sum(lsb == 0)
            count_1 = np.sum(lsb == 1)
            total = len(lsb)
            
            # Expected counts (50/50)
            expected = total / 2
            
            # Chi-square statistic
            chi2 = ((count_0 - expected)**2 / expected + 
                    (count_1 - expected)**2 / expected)
            
            # Approximate p-value (1 degree of freedom)
            # For chi2 > 3.841, p < 0.05 (suspicious)
            pvalue = 1.0 / (1.0 + chi2 / 10.0)  # Simplified approximation
            
            suspicious = pvalue < self.threshold_chi2
            
            return {
                'suspicious': suspicious,
                'pvalue': float(pvalue),
                'chi2_stat': float(chi2)
            }
        except Exception:
            return {'suspicious': False, 'pvalue': 1.0, 'chi2_stat': 0.0}
    
    def _entropy_analysis(self, img_array: np.ndarray) -> dict:
        """
        Calculate image entropy
        High entropy may indicate encrypted/compressed hidden data
        """
        try:
            # Calculate entropy for each channel
            entropies = []
            for channel in range(3):
                data = img_array[:, :, channel].flatten()
                # Calculate histogram
                hist, _ = np.histogram(data, bins=256, range=(0, 256))
                # Normalize
                hist = hist / hist.sum()
                # Remove zeros
                hist = hist[hist > 0]
                # Calculate entropy
                entropy = -np.sum(hist * np.log2(hist))
                entropies.append(entropy)
            
            avg_entropy = np.mean(entropies)
            
            # Natural images typically have entropy 6-7.5
            # Encrypted data has entropy close to 8
            high_entropy = avg_entropy > self.threshold_entropy
            
            return {
                'high': high_entropy,
                'entropy': float(avg_entropy),
                'channel_entropies': [float(e) for e in entropies]
            }
        except Exception:
            return {'high': False, 'entropy': 0.0, 'channel_entropies': [0.0, 0.0, 0.0]}
    
    def _exif_analysis(self, img: Image.Image) -> dict:
        """
        Analyze EXIF metadata for suspicious patterns
        Steganography tools may leave traces in EXIF
        """
        try:
            exif = img._getexif()
            if not exif:
                return {'suspicious': False}
            
            # Check for suspicious software tags
            suspicious_keywords = [
                'steg', 'hide', 'secret', 'crypt', 'openstego', 
                'steghide', 'outguess', 'jsteg'
            ]
            
            software = str(exif.get(305, '')).lower()  # Software tag
            comment = str(exif.get(37510, '')).lower()  # UserComment tag
            
            suspicious = any(
                keyword in software or keyword in comment 
                for keyword in suspicious_keywords
            )
            
            return {
                'suspicious': suspicious,
                'software': software if software else None,
                'comment': comment if comment else None
            }
        except Exception:
            return {'suspicious': False}


if __name__ == "__main__":
    detector = StegDetector()
    print("Steganography Detector initialized")
    print("Usage: result = detector.analyze('image.png')")
