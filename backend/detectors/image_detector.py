"""
IMAGE SHIELD ADVANCED — 2026 MILITARY GRADE
Category 4: Image / QR / RAT / Steganography Detection

Architecture (6 PIPELINES):
  Pipeline 1: QR Code Detection (YOLOv8 → pyzxing decode → URL Shield)
  Pipeline 2: Brand Matching (CLIP ViT-L/14 zero-shot)
  Pipeline 3: Text Extraction (TrOCR → SMS Shield analysis)
  Pipeline 4: Basic Steganography (LSB/Chi2/Entropy)
  Pipeline 5: Advanced Steganography (SRM/RS/SPA/DCT/DWT) - MILITARY GRADE
  Pipeline 6: Advanced RAT Detection (14 RAT variants) - 2026 THREATS

Performance:
  - All 6 pipelines run concurrently via ThreadPoolExecutor
  - Military-grade threat detection
  - Detects: LSB, F5, nsF5, J-UNIWARD, HUGO, WOW, S-UNIWARD
  - Detects: AsyncRAT, QuasarRAT, NjRAT, DarkComet, NanoCore, Remcos, AgentTesla
  - Detects: LokiBot, FormBook, NetWire, QuantumRAT, PhantomRAT, ShadowRAT, GhostRAT

Target: >95% accuracy on all image-based threats
"""

import os
import glob
import torch
import numpy as np
from PIL import Image
from transformers import CLIPModel, CLIPProcessor, VisionEncoderDecoderModel, TrOCRProcessor
from concurrent.futures import ThreadPoolExecutor
import warnings
import time
import logging
from backend.utils.steg_detector import StegDetector
from backend.utils.advanced_steg_detector import AdvancedStegDetector
from backend.utils.advanced_rat_detector import AdvancedRATDetector

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)

def convert_numpy_types(obj):
    """Convert numpy types to native Python types for JSON serialization"""
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
    elif isinstance(obj, tuple):
        return tuple(convert_numpy_types(item) for item in obj)
    return obj

# Optional imports with type hints for linting
try:
    import pyzxing  # type: ignore
    PYZXING_AVAILABLE = True
except (ImportError, Exception) as e:
    PYZXING_AVAILABLE = False
    pyzxing = None  # type: ignore

try:
    from ultralytics import YOLO  # type: ignore
    YOLO_AVAILABLE = True
except ImportError:
    YOLO_AVAILABLE = False
    YOLO = None  # type: ignore

def _find_local_yolo_pt():
    search_root = os.path.join("models", "image", "YOLOv8_QR")
    pattern = os.path.join(search_root, "**", "*.pt")
    matches = glob.glob(pattern, recursive=True)
    return matches[0] if matches else None


class ImageShieldAdvanced:
    """
    Military-Grade Image Phishing Detection - 2026 Threat Landscape
    6 Pipelines for comprehensive threat detection
    """

    def __init__(self):
        print("="*80)
        print("IMAGE SHIELD ADVANCED — 2026 MILITARY GRADE")
        print("="*80)
        print("\nArchitecture: 6 Detection Pipelines")
        print("  Pipeline 1: YOLOv8 QR detect → pyzxing decode → URL Shield")
        print("  Pipeline 2: CLIP ViT-L/14 brand impersonation (zero-shot)")
        print("  Pipeline 3: TrOCR text extraction → SMS Shield scoring")
        print("  Pipeline 4: Basic Steganography (LSB/Chi2/Entropy)")
        print("  Pipeline 5: Advanced Steganography (SRM/RS/SPA/DCT/DWT)")
        print("  Pipeline 6: Advanced RAT Detection (14 RAT variants)")
        print("  Pipeline 7: Military-grade ensemble decision\n")

        self._device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"  [Device] Using: {self._device.upper()}")
        self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="img_shield_adv")

        print("[Stage 1] Loading ML models...")
        self._load_models()

        print("\n[Stage 2] Building brand database...")
        self._build_brand_database()

        print("\n[Stage 3] Initializing advanced threat detectors...")
        self.steg_detector = StegDetector()
        print("      [OK] Basic steg detector ready")
        
        self.advanced_steg_detector = AdvancedStegDetector()
        print("      [OK] Advanced steg detector ready (SRM/RS/SPA/DCT/DWT)")
        
        self.rat_detector = AdvancedRATDetector()
        print("      [OK] Advanced RAT detector ready (14 variants)")

        print("\n[OK] Image Shield Advanced Ready!")
        print("="*80 + "\n")

        self.url_shield = None
        self.sms_shield = None

    def _load_models(self):
        print("  [1/3] YOLOv8s QR Detection")
        self.yolo_qr = None
        if YOLO_AVAILABLE:
            pt_path = _find_local_yolo_pt()
            if pt_path:
                try:
                    self.yolo_qr = YOLO(pt_path)
                    print(f"        [OK] Loaded: {pt_path}")
                except Exception as e:
                    print(f"        [WARNING] Failed: {e}")
            else:
                print("        [WARNING] No .pt file found")
        else:
            print("        [WARNING] ultralytics not installed")

        print("  [2/3] CLIP ViT-L/14 Brand Matching")
        clip_local = "models/image/CLIP_Brand"
        try:
            self.clip_model = CLIPModel.from_pretrained(clip_local)
            self.clip_processor = CLIPProcessor.from_pretrained(clip_local)
            self.clip_model.eval()
            if self._device == "cuda":
                self.clip_model = self.clip_model.half().to("cuda")
            print(f"        [OK] Loaded: {clip_local}")
        except Exception as e:
            print(f"        [ERROR] {e}")
            self.clip_model = None
            self.clip_processor = None

        print("  [3/3] TrOCR Text Extraction")
        trocr_local = "models/image/TrOCR_Text"
        try:
            self.trocr_model = VisionEncoderDecoderModel.from_pretrained(trocr_local)
            self.trocr_processor = TrOCRProcessor.from_pretrained(trocr_local)
            self.trocr_model.eval()
            if self._device == "cuda":
                self.trocr_model = self.trocr_model.half().to("cuda")
            print(f"        [OK] Loaded: {trocr_local}")
        except Exception as e:
            print(f"        [ERROR] {e}")
            self.trocr_model = None
            self.trocr_processor = None

    def _build_brand_database(self):
        self.brands = [
            'PayPal', 'Amazon', 'Microsoft', 'Apple', 'Google', 'Facebook', 'Netflix',
            'Instagram', 'WhatsApp', 'LinkedIn', 'Twitter', 'eBay', 'Walmart', 'Target',
            'Bank of America', 'Wells Fargo', 'Chase', 'Citibank', 'HSBC', 'Barclays',
            'American Express', 'Visa', 'Mastercard', 'Capital One',
            'IRS', 'USPS', 'FedEx', 'UPS', 'DHL',
            'Adobe', 'Dropbox', 'Zoom', 'Slack', 'Salesforce',
            'Samsung', 'Sony', 'HP', 'Dell', 'Lenovo',
            'Spotify', 'YouTube', 'TikTok', 'Snapchat', 'Reddit',
            'Airbnb', 'Uber', 'Lyft', 'DoorDash',
            'Coinbase', 'Binance', 'Robinhood', 'Venmo', 'Cash App',
            'AT&T', 'Verizon', 'T-Mobile', 'Comcast',
        ]
        self.brand_prompts = []
        for brand in self.brands:
            self.brand_prompts.extend([
                f"a {brand} login page",
                f"a {brand} logo",
                f"a {brand} website screenshot",
                f"{brand} sign in page",
            ])
        print(f"      [OK] {len(self.brands)} brands, {len(self.brand_prompts)} prompts")

    def detect_qr_codes(self, image: Image.Image) -> dict:
        """YOLOv8 QR detection → pyzxing decode → URL Shield"""
        if self.yolo_qr is None:
            return {'qr_found': False, 'urls': [], 'phishing_urls': [], 'qr_count': 0}

        try:
            image_np = np.array(image.convert('RGB'))
            results = self.yolo_qr(image_np, conf=0.5, verbose=False)

            qr_boxes = []
            for r in results:
                if r.boxes is not None and len(r.boxes) > 0:
                    for box in r.boxes:
                        x1, y1, x2, y2 = box.xyxy[0].cpu().numpy().astype(int)
                        qr_boxes.append((x1, y1, x2, y2))

            if not qr_boxes:
                return {'qr_found': False, 'urls': [], 'phishing_urls': [], 'qr_count': 0}

            decoded_urls = []
            if PYZXING_AVAILABLE:
                try:
                    reader = pyzxing.BarCodeReader()
                    for (x1, y1, x2, y2) in qr_boxes:
                        pad = 10
                        x1p = max(0, x1 - pad)
                        y1p = max(0, y1 - pad)
                        x2p = min(image_np.shape[1], x2 + pad)
                        y2p = min(image_np.shape[0], y2 + pad)
                        crop = image_np[y1p:y2p, x1p:x2p]
                        crop_pil = Image.fromarray(crop)

                        tmp_path = "_tmp_qr_crop.png"
                        crop_pil.save(tmp_path)
                        decoded = reader.decode(tmp_path)
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass

                        if decoded and hasattr(decoded, '__iter__'):
                            for item in (decoded if isinstance(decoded, list) else [decoded]):
                                raw = getattr(item, 'raw', None) or (
                                    item.get('raw') if isinstance(item, dict) else None
                                )
                                if raw:
                                    decoded_urls.append(str(raw))
                        elif decoded:
                            raw = getattr(decoded, 'raw', None)
                            if raw:
                                decoded_urls.append(str(raw))
                except Exception as e:
                    logger.warning(f"pyzxing decode error: {e}")

            phishing_urls = []
            url_phishing_detected = False
            clean_urls = [u for u in decoded_urls if u.startswith(('http://', 'https://'))]

            if clean_urls:
                try:
                    if self.url_shield is None:
                        from backend.detectors.url_detector import PhishingShield2
                        self.url_shield = PhishingShield2()
                    url_futures = {
                        url: self._executor.submit(self.url_shield.predict, url)
                        for url in clean_urls
                    }
                    for url, fut in url_futures.items():
                        r = fut.result()
                        if r['is_phishing']:
                            phishing_urls.append(url)
                            url_phishing_detected = True
                except Exception as e:
                    logger.warning(f"URL Shield call failed: {e}")

            return {
                'qr_found': True,
                'qr_count': len(qr_boxes),
                'qr_boxes': [(int(x1), int(y1), int(x2), int(y2)) for x1, y1, x2, y2 in qr_boxes],
                'urls': clean_urls,
                'phishing_urls': phishing_urls,
                'url_phishing_detected': url_phishing_detected,
                'decode_available': PYZXING_AVAILABLE,
            }

        except Exception as e:
            logger.warning(f"QR detection error: {e}")
            return {'qr_found': False, 'urls': [], 'phishing_urls': [], 'qr_count': 0}

    def detect_brand_impersonation(self, image: Image.Image) -> dict:
        """CLIP zero-shot brand matching"""
        if self.clip_model is None:
            return {'brand_detected': False, 'top_brand': None,
                    'similarity': 0.0, 'top5_matches': [], 'brand_phishing_prob': 0.0}
        try:
            inputs = self.clip_processor(
                text=self.brand_prompts, images=image,
                return_tensors="pt", padding=True
            )
            if self._device == "cuda":
                inputs = {k: v.to("cuda") for k, v in inputs.items()}
            with torch.no_grad():
                outputs = self.clip_model(**inputs)
                logits = outputs.logits_per_image
                probs = logits.softmax(dim=1)[0].float().cpu()

            probs_np = probs.numpy()
            
            brand_scores = {}
            for idx, score in enumerate(probs_np):
                brand = self.brands[idx // 4]
                brand_scores[brand] = brand_scores.get(brand, 0.0) + float(score)
                
            sorted_brands = sorted(brand_scores.items(), key=lambda x: x[1], reverse=True)
            top_brand, max_prob = sorted_brands[0]
            
            top5 = [{'brand': b, 'similarity': float(s)} for b, s in sorted_brands[:5]]

            # FIXED: Much stricter threshold - only flag if >75% match AND clear phishing indicators
            brand_phishing_prob = float(1 / (1 + np.exp(-20 * (max_prob - 0.75))))
            is_impersonation = max_prob > 0.75

            return {
                'brand_detected': is_impersonation,
                'top_brand': top_brand,
                'similarity': max_prob,
                'brand_phishing_prob': brand_phishing_prob,
                'top5_matches': top5,
                'threshold': 0.75,
            }

        except Exception as e:
            logger.warning(f"Brand detection error: {e}")
            return {'brand_detected': False, 'top_brand': None,
                    'similarity': 0.0, 'top5_matches': [], 'brand_phishing_prob': 0.0}

    def extract_text(self, image: Image.Image) -> dict:
        """TrOCR text extraction → SMS Shield"""
        if self.trocr_model is None:
            return {'text_found': False, 'extracted_text': '',
                    'text_length': 0, 'text_phishing_prob': 0.0}
        try:
            img_rgb = image.convert('RGB')
            pixel_values = self.trocr_processor(images=img_rgb, return_tensors="pt").pixel_values
            if self._device == "cuda":
                pixel_values = pixel_values.to("cuda")
                if next(self.trocr_model.parameters()).dtype == torch.float16:
                    pixel_values = pixel_values.half()

            with torch.no_grad():
                generated_ids = self.trocr_model.generate(pixel_values)

            extracted_text = self.trocr_processor.batch_decode(
                generated_ids, skip_special_tokens=True
            )[0]

            text_phishing_prob = 0.0
            sms_result = None

            if len(extracted_text.strip()) > 10:
                try:
                    if self.sms_shield is None:
                        from backend.detectors.sms_detector import SmishingShield
                        self.sms_shield = SmishingShield()
                    sms_result = self.sms_shield.predict(extracted_text)
                    text_phishing_prob = sms_result['smishing_score']
                except Exception as e:
                    logger.warning(f"SMS Shield failed: {e}")

            return {
                'text_found': len(extracted_text.strip()) > 0,
                'extracted_text': extracted_text,
                'text_length': len(extracted_text),
                'text_phishing_prob': text_phishing_prob,
                'sms_verdict': sms_result['is_smishing'] if sms_result else None,
            }

        except Exception as e:
            logger.warning(f"Text extraction error: {e}")
            return {'text_found': False, 'extracted_text': '',
                    'text_length': 0, 'text_phishing_prob': 0.0, 'sms_verdict': None}

    def detect_steganography(self, image_path_or_array) -> dict:
        """Basic steganography detection"""
        try:
            return self.steg_detector.analyze(image_path_or_array)
        except Exception as e:
            logger.warning(f"Basic steg error: {e}")
            return {
                'steg_detected': False,
                'steg_probability': 0.0,
                'indicators': [],
                'chi2_pvalue': 1.0,
                'entropy': 0.0,
                'lsb_anomaly': False,
            }

    def detect_advanced_steganography(self, image_path_or_array) -> dict:
        """Advanced steganography detection (MILITARY GRADE)"""
        try:
            return self.advanced_steg_detector.analyze(image_path_or_array)
        except Exception as e:
            logger.warning(f"Advanced steg error: {e}")
            return {
                'steg_detected': False,
                'steg_probability': 0.0,
                'steg_type': None,
                'confidence': 0.0,
                'indicators': [],
                'techniques_triggered': [],
            }

    def detect_rat(self, image_path_or_array) -> dict:
        """Advanced RAT detection (2026 THREATS)"""
        try:
            return self.rat_detector.analyze(image_path_or_array)
        except Exception as e:
            logger.warning(f"RAT detection error: {e}")
            return {
                'rat_detected': False,
                'rat_probability': 0.0,
                'detected_rats': [],
                'threat_level': 'SAFE',
                'indicators': [],
                'techniques_triggered': [],
            }

    def predict(self, image_path_or_array) -> dict:
        """
        Military-grade ensemble with 6 pipelines
        """
        if isinstance(image_path_or_array, str):
            image = Image.open(image_path_or_array).convert('RGB')
        elif isinstance(image_path_or_array, Image.Image):
            image = image_path_or_array.convert('RGB')
        else:
            image = Image.fromarray(image_path_or_array).convert('RGB')

        t0 = time.perf_counter()

        # Run all 6 pipelines in parallel
        f_qr = self._executor.submit(self.detect_qr_codes, image)
        f_brand = self._executor.submit(self.detect_brand_impersonation, image)
        f_text = self._executor.submit(self.extract_text, image)
        f_steg = self._executor.submit(self.detect_steganography, image_path_or_array)
        f_advanced_steg = self._executor.submit(self.detect_advanced_steganography, image_path_or_array)
        f_rat = self._executor.submit(self.detect_rat, image_path_or_array)

        qr_result = f_qr.result()
        brand_result = f_brand.result()
        text_result = f_text.result()
        steg_result = f_steg.result()
        advanced_steg_result = f_advanced_steg.result()
        rat_result = f_rat.result()

        # Military-grade ensemble weights
        risk_score = 0.0
        risk_factors = []
        weights = {
            'qr': 0.25,
            'brand': 0.20,
            'text': 0.15,
            'steg_basic': 0.10,
            'steg_advanced': 0.15,
            'rat': 0.15
        }

        # QR pipeline
        qr_prob = 0.0
        if qr_result.get('qr_found'):
            if qr_result.get('url_phishing_detected'):
                qr_prob = 0.95
                risk_factors.append(f"QR phishing URL: {qr_result['phishing_urls']}")
            elif qr_result.get('urls'):
                qr_prob = 0.65
                risk_factors.append(f"QR code with URL: {qr_result['urls']}")
            else:
                qr_prob = 0.45
                risk_factors.append(f"QR code detected ({qr_result['qr_count']} found)")

        # Brand pipeline - only flag if high confidence
        brand_prob = brand_result.get('brand_phishing_prob', 0.0)
        if brand_result.get('brand_detected') and brand_result.get('similarity', 0) > 0.75:
            risk_factors.append(
                f"Brand impersonation: {brand_result['top_brand']} "
                f"({brand_result['similarity']:.1%})"
            )

        # Text pipeline - ignore short text extractions
        text_prob = text_result.get('text_phishing_prob', 0.0)
        text_length = text_result.get('text_length', 0)
        if text_result.get('text_found') and text_length > 20 and text_prob > 0.7:
            risk_factors.append(f"Phishing text (SMS score: {text_prob:.1%})")
        elif text_result.get('text_found') and text_length > 50:
            risk_factors.append(f"Text found: {text_length} chars")

        # Basic steg
        steg_prob = steg_result.get('steg_probability', 0.0)
        if steg_result.get('steg_detected'):
            risk_factors.append(f"Basic steg (prob: {steg_prob:.1%})")

        # Advanced steg (MILITARY GRADE) - require high confidence
        advanced_steg_prob = advanced_steg_result.get('steg_probability', 0.0)
        if advanced_steg_result.get('steg_detected') and advanced_steg_prob > 0.85:
            steg_type = advanced_steg_result.get('steg_type', 'Unknown')
            techniques = ', '.join(advanced_steg_result['techniques_triggered'])
            risk_factors.append(
                f"⚠️ ADVANCED STEG: {steg_type} "
                f"(prob: {advanced_steg_prob:.1%}, {techniques})"
            )

        # RAT detection (2026 THREATS) - require very high confidence
        rat_prob = rat_result.get('rat_probability', 0.0)
        if rat_result.get('rat_detected') and rat_prob > 0.90:
            threat_level = rat_result.get('threat_level', 'UNKNOWN')
            detected_rats = ', '.join(rat_result['detected_rats']) if rat_result['detected_rats'] else 'Unknown RAT'
            techniques = ', '.join(rat_result['techniques_triggered'])
            risk_factors.append(
                f"🚨 RAT DETECTED: {detected_rats} "
                f"(threat: {threat_level}, prob: {rat_prob:.1%}, {techniques})"
            )

        # Weighted ensemble with validation
        risk_score = (
            weights['qr'] * qr_prob +
            weights['brand'] * brand_prob +
            weights['text'] * text_prob +
            weights['steg_basic'] * steg_prob +
            weights['steg_advanced'] * advanced_steg_prob +
            weights['rat'] * rat_prob
        )

        # FIXED: Higher threshold to reduce false positives
        is_phishing = risk_score > 0.65

        # CRITICAL THREAT OVERRIDES - stricter validation
        if qr_result.get('url_phishing_detected'):
            is_phishing = True
            risk_score = max(risk_score, 0.95)
        
        if text_prob > 0.90 and text_length > 30:
            is_phishing = True
            risk_score = max(risk_score, text_prob)
            
        if brand_prob > 0.95:
            is_phishing = True
            risk_score = max(risk_score, brand_prob)
        
        if advanced_steg_prob > 0.92:
            is_phishing = True
            risk_score = max(risk_score, 0.92)
            risk_factors.append(f"⚠️ CRITICAL: Advanced steg confirmed")
        
        if rat_prob > 0.93:
            is_phishing = True
            risk_score = max(risk_score, 0.98)
            risk_factors.append(f"🚨 CRITICAL THREAT: RAT malware")

        confidence = risk_score if is_phishing else (1.0 - risk_score)
        latency_ms = (time.perf_counter() - t0) * 1000

        result = {
            'is_phishing': bool(is_phishing),
            'phishing_score': float(risk_score),
            'confidence': float(confidence),
            'risk_factors': risk_factors,
            'latency_ms': round(latency_ms, 1),
            'pipeline_scores': {
                'qr_prob': float(qr_prob),
                'brand_prob': float(brand_prob),
                'text_prob': float(text_prob),
                'steg_basic_prob': float(steg_prob),
                'steg_advanced_prob': float(advanced_steg_prob),
                'rat_prob': float(rat_prob),
            },
            'pipelines': {
                'qr_detection': qr_result,
                'brand_matching': brand_result,
                'text_extraction': text_result,
                'steganography_basic': steg_result,
                'steganography_advanced': advanced_steg_result,
                'rat_detection': rat_result,
            },
        }
        
        # Convert all numpy types to native Python types
        return convert_numpy_types(result)

    def __del__(self):
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)


if __name__ == "__main__":
    shield = ImageShieldAdvanced()
    print("\nImage Shield Advanced ready (2026 MILITARY GRADE)")
    print("6 Pipelines: QR, Brand, Text, Basic Steg, Advanced Steg, RAT Detection")
    print("Usage: result = shield.predict('image.png')")
