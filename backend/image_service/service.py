import io
import time
from typing import Dict

import numpy as np
from PIL import Image

from backend.image_service.file_analysis.entropy_analyzer import EntropyAnalyzer
from backend.image_service.file_analysis.file_type_validator import FileTypeValidator
from backend.image_service.file_analysis.polyglot_detector import PolyglotDetector
from backend.image_service.qr_pipeline.qr_decoder import QRDecoder
from backend.image_service.qr_pipeline.qr_detector import QRDetector
from backend.image_service.rat_steg_pipeline.dct_dwt_analyzer import DCTDWTAnalyzer
from backend.image_service.rat_steg_pipeline.exif_forensics import EXIFForensics
from backend.image_service.rat_steg_pipeline.icc_profile_analyzer import ICCProfileAnalyzer
from backend.image_service.rat_steg_pipeline.lsb_analyzer import LSBAnalyzer
from backend.image_service.rat_steg_pipeline.steg_cnn_model import StegCNNDetector
from backend.image_service.rat_steg_pipeline.svg_xss_detector import SVGXSSDetector
from backend.image_service.sandbox.image_sandbox_client import ImageSandboxClient
from backend.image_service.visual_pipeline.clip_brand_engine import CLIPBrandEngine
from backend.image_service.visual_pipeline.efficientnet_scorer import EfficientNetScorer
from backend.image_service.visual_pipeline.layout_analyzer import LayoutAnalyzer
from backend.image_service.visual_pipeline.trocr_extractor import TrOCRExtractor

validators = {}


async def load_image_models():
    global validators
    validators = {
        'file_type': FileTypeValidator(),
        'polyglot': PolyglotDetector(),
        'entropy': EntropyAnalyzer(),
        'lsb': LSBAnalyzer(),
        'dctdwt': DCTDWTAnalyzer(),
        'exif': EXIFForensics(),
        'svg': SVGXSSDetector(),
        'icc': ICCProfileAnalyzer(),
        'steg_cnn': StegCNNDetector(),
        'qr_detector': QRDetector(),
        'qr_decoder': QRDecoder(),
        'clip': CLIPBrandEngine(),
        'layout': LayoutAnalyzer(),
        'efficientnet': EfficientNetScorer(),
        'trocr': TrOCRExtractor(),
        'sandbox': ImageSandboxClient(),
    }


def get_image_model_status() -> Dict[str, bool]:
    return {k: True for k in validators.keys()}


async def analyze_image(image_bytes: bytes, context: str = 'unknown', run_sandbox: bool = False) -> Dict:
    start_time = time.time()

    file_type_info = validators['file_type'].validate(image_bytes, 'upload.bin')
    detected_type = (file_type_info.get('actual_type') or 'UNKNOWN').upper()
    file_size = len(image_bytes)

    polyglot = validators['polyglot'].detect(image_bytes, 'bin')
    entropy = validators['entropy'].analyze(image_bytes)
    lsb = validators['lsb'].analyze(image_bytes)
    dctdwt = validators['dctdwt'].analyze(image_bytes)
    exif = validators['exif'].analyze(image_bytes)
    icc = validators['icc'].analyze(image_bytes)

    svg_xss = {'svg_xss_found': False}
    if 'SVG' in detected_type or image_bytes.lstrip().startswith(b'<svg'):
        svg_xss = validators['svg'].detect(image_bytes)

    steg_score = validators['steg_cnn'].predict(image_bytes)

    qr_urls = []
    qr_count = 0
    try:
        arr = np.array(Image.open(io.BytesIO(image_bytes)).convert('RGB'))
        boxes = validators['qr_detector'].detect(image_bytes)
        for x, y, w, h in boxes:
            crop = arr[y:y+h, x:x+w]
            decoded = validators['qr_decoder'].decode_qr_array(crop)
            if decoded.get('content'):
                qr_count += 1
                if decoded['content'].startswith(('http://', 'https://')):
                    qr_urls.append(decoded['content'])
    except Exception:
        pass

    brand_info = validators['clip'].score_brand_similarity(image_bytes)
    extracted_text = validators['trocr'].extract_text(image_bytes)
    layout = validators['layout'].analyze_layout(extracted_text)
    visual_score = validators['efficientnet'].score(image_bytes)

    sandbox = {'sandbox_detonated': False, 'c2_beacons_detected': False, 'c2_domains': []}
    should_sandbox = run_sandbox or polyglot.get('is_polyglot') or exif.get('exif_malware_found') or svg_xss.get('svg_xss_found')
    if should_sandbox:
        sandbox = await validators['sandbox'].detonate(image_bytes, filename='upload.bin')

    model_scores = {
        'clip_brand': float(brand_info.get('brand_impersonation_score', 0.0)),
        'layoutlm': float(layout.get('layout_confidence', 0.0)),
        'efficientnet': float(visual_score),
        'steg_cnn': float(steg_score),
        'dct_steg': float(dctdwt.get('dct_steg_score', 0.0)),
        'qr_detection': 1.0 if qr_count > 0 else 0.0,
    }

    indicators = []
    if polyglot.get('is_polyglot'):
        indicators.append('Polyglot file characteristics detected')
    if lsb.get('steganography_detected'):
        indicators.append('LSB steganography indicators detected')
    if svg_xss.get('svg_xss_found'):
        indicators.append('SVG script/XSS payload detected')
    if exif.get('exif_malware_found'):
        indicators.append('Suspicious EXIF payload detected')
    if sandbox.get('c2_beacons_detected'):
        indicators.append('C2 beacon behavior detected in sandbox')

    return {
        'model_scores': model_scores,
        'final_score': sum(model_scores.values()) / len(model_scores),
        'indicators': indicators,
        'metadata': {
            'file_type_detected': detected_type,
            'file_size_bytes': file_size,
            'is_polyglot': bool(polyglot.get('is_polyglot', False)),
            'steganography_detected': bool(lsb.get('steganography_detected', False) or steg_score > 0.7),
            'steg_method': lsb.get('method'),
            'steg_confidence': float(max(lsb.get('confidence', 0.0), steg_score)),
            'chi_square_pvalue': float(lsb.get('chi_square_pvalue', 1.0)),
            'svg_xss_found': bool(svg_xss.get('svg_xss_found', False)),
            'exif_malware_found': bool(exif.get('exif_malware_found', False)),
            'qr_codes_found': int(qr_count),
            'qr_decoded_urls': qr_urls,
            'brands_detected': brand_info.get('brands_detected', []),
            'brand_impersonation_score': float(brand_info.get('brand_impersonation_score', 0.0)),
            'is_fake_login_page': bool(layout.get('is_fake_login_page', False)),
            'layout_confidence': float(layout.get('layout_confidence', 0.0)),
            'text_extracted': extracted_text,
            'rat_family_suspected': 'unknown' if sandbox.get('c2_beacons_detected') else None,
            'sandbox_detonated': bool(sandbox.get('sandbox_detonated', False)),
            'c2_beacons_detected': bool(sandbox.get('c2_beacons_detected', False)),
            'c2_domains': sandbox.get('c2_domains', []),
        },
        'latency_ms': (time.time() - start_time) * 1000,
    }
