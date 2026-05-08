"""
Phishing Shield 2.0 - Main Application
Flask web server with 4 detection categories
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import sys
import io
import os
import threading
import time
import logging

# Fix encoding for Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import detectors
from backend.detectors.url_detector import PhishingShield2
from backend.detectors.sms_detector import SmishingShield
from backend.detectors.email_detector import EmailShield
from backend.detectors.image_detector import ImageShieldAdvanced

# Import configuration
from config.config import (
    UPLOAD_FOLDER, ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH,
    FLASK_CONFIG, LOGGING_CONFIG, init_directories
)

# Initialize directories
init_directories()

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOGGING_CONFIG['level']),
    format=LOGGING_CONFIG['format']
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, 
            template_folder='frontend',
            static_folder='frontend/static')
CORS(app)

# Configure app
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ── Thread-safe lazy model loading ────────────────────────────────────────────
_url_shield = None
_sms_shield = None
_email_shield = None
_image_shield = None
_url_lock = threading.Lock()
_sms_lock = threading.Lock()
_email_lock = threading.Lock()
_image_lock = threading.Lock()


def get_url_shield() -> PhishingShield2:
    """Get or initialize URL Shield"""
    global _url_shield
    with _url_lock:
        if _url_shield is None:
            logger.info("Loading URL Shield...")
            _url_shield = PhishingShield2()
            logger.info("URL Shield ready.")
    return _url_shield


def get_sms_shield() -> SmishingShield:
    """Get or initialize SMS Shield"""
    global _sms_shield
    with _sms_lock:
        if _sms_shield is None:
            logger.info("Loading SMS Shield...")
            _sms_shield = SmishingShield()
            logger.info("SMS Shield ready.")
    return _sms_shield


def get_email_shield() -> EmailShield:
    """Get or initialize Email Shield"""
    global _email_shield
    with _email_lock:
        if _email_shield is None:
            logger.info("Loading Email Shield...")
            _email_shield = EmailShield()
            logger.info("Email Shield ready.")
    return _email_shield


def get_image_shield() -> ImageShieldAdvanced:
    """Get or initialize Image Shield"""
    global _image_shield
    with _image_lock:
        if _image_shield is None:
            logger.info("Loading Image Shield Advanced (MILITARY GRADE 2026)...")
            _image_shield = ImageShieldAdvanced()
            logger.info("Image Shield Advanced ready.")
    return _image_shield


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve main page"""
    return render_template('index.html')


@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory('frontend/static', filename)


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze URL for phishing"""
    try:
        data = request.get_json()
        url = (data.get('url') or '').strip()
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        shield = get_url_shield()
        result = shield.predict(url)

        response = {
            'url': result['url'],
            'is_phishing': result['is_phishing'],
            'phishing_score': result['phishing_score'],
            'confidence': result['confidence'],
            'votes': result['votes'],
            'latency_ms': result.get('latency_ms', 0),
            'individual_results': {
                'u1': {
                    'model': 'U1 (URLNet / BERT-base)',
                    'prediction': result['models']['U1_URLNet']['prediction'],
                    'confidence': result['models']['U1_URLNet']['confidence'],
                    'is_phishing': result['models']['U1_URLNet']['is_phishing'],
                },
                'u2': {
                    'model': 'U2 (DeBERTa / BERT-large)',
                    'prediction': result['models']['U2_DeBERTa']['prediction'],
                    'confidence': result['models']['U2_DeBERTa']['confidence'],
                    'is_phishing': result['models']['U2_DeBERTa']['is_phishing'],
                },
                'u4': {
                    'model': 'U4 (XGBoost / LinearSVM)',
                    'prediction': result['models']['U4_XGBoost']['prediction'],
                    'confidence': result['models']['U4_XGBoost']['confidence'],
                    'is_phishing': result['models']['U4_XGBoost']['is_phishing'],
                },
                'features': {
                    'model': 'Feature Engineering',
                    'prediction': 'Phishing' if result['models']['Features']['score'] > 0.5 else 'Benign',
                    'confidence': result['models']['Features']['score'],
                    'is_phishing': result['models']['Features']['score'] > 0.5,
                    'typosquatting_score': result['models']['Features'].get('typosquatting_score', 0),
                    'is_new_domain': result['models']['Features'].get('is_new_domain', False),
                    'domain_age_days': result['models']['Features'].get('domain_age_days', -1),
                },
            },
        }
        return jsonify(response), 200

    except Exception as e:
        logger.exception("Error in /analyze")
        return jsonify({'error': str(e)}), 500


@app.route('/analyze-sms', methods=['POST'])
def analyze_sms():
    """Analyze SMS for smishing"""
    try:
        data = request.get_json()
        sms_text = (data.get('text') or '').strip()
        if not sms_text:
            return jsonify({'error': 'SMS text is required'}), 400

        shield = get_sms_shield()
        result = shield.predict(sms_text)

        response = {
            'text': result['text'],
            'is_smishing': result['is_smishing'],
            'smishing_score': result['smishing_score'],
            'confidence': result['confidence'],
            'votes': result['votes'],
            'latency_ms': result.get('latency_ms', 0),
            'individual_results': {
                's1': {
                    'model': 'S1 (SecureBERT)',
                    'prediction': result['models']['S1_SecureBERT']['prediction'],
                    'confidence': result['models']['S1_SecureBERT']['confidence'],
                    'is_phishing': result['models']['S1_SecureBERT']['prediction'] == 'Spam',
                },
                's3': {
                    'model': 'S3 (RoBERTa SMS)',
                    'prediction': result['models']['S3_RoBERTa_SMS']['prediction'],
                    'confidence': result['models']['S3_RoBERTa_SMS']['confidence'],
                    'is_phishing': result['models']['S3_RoBERTa_SMS']['prediction'] == 'Spam',
                },
                's4': {
                    'model': 'S4 (mDeBERTa-v3)',
                    'prediction': result['models']['S4_mDeBERTa']['prediction'],
                    'confidence': result['models']['S4_mDeBERTa']['confidence'],
                    'is_phishing': result['models']['S4_mDeBERTa']['prediction'] == 'Spam',
                },
                's5': {
                    'model': 'S5 (Enterprise Spam)',
                    'prediction': result['models']['S5_RoBERTa_Enterprise']['prediction'],
                    'confidence': result['models']['S5_RoBERTa_Enterprise']['confidence'],
                    'is_phishing': result['models']['S5_RoBERTa_Enterprise']['prediction'] == 'Spam',
                },
                'features': {
                    'model': 'SMS Features',
                    'prediction': 'Smishing' if result['models']['Features']['score'] > 0.5 else 'Legitimate',
                    'confidence': result['models']['Features']['score'],
                    'is_phishing': result['models']['Features']['score'] > 0.5,
                },
            },
            'risk_indicators': result['models']['Features']['risk_indicators'],
        }

        if 'url_analysis' in result:
            response['url_analysis'] = result['url_analysis']
            response['urls_found'] = result['urls_found']
            response['phishing_urls_detected'] = result['phishing_urls_detected']

        return jsonify(response), 200

    except Exception as e:
        logger.exception("Error in /analyze-sms")
        return jsonify({'error': str(e)}), 500


@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    """Analyze email for phishing"""
    try:
        data = request.get_json()
        email_content = (data.get('email') or '').strip()
        if not email_content:
            return jsonify({'error': 'Email content is required'}), 400

        shield = get_email_shield()
        result = shield.predict(email_content)

        response = {
            'email_data': {
                **result['email_data'],
                'reply_to': result['email_data'].get('reply_to', ''),
            },
            'is_phishing': result['is_phishing'],
            'phishing_score': result['phishing_score'],
            'confidence': result['confidence'],
            'votes': result['votes'],
            'latency_ms': result.get('latency_ms', 0),
            'spoofing': result.get('spoofing', {}),
            'individual_results': {
                'e1': {
                    'model': 'E1 (ScamLLM)',
                    'prediction': 'Phishing' if result['models']['E1_ScamLLM']['is_phishing'] else 'Legitimate',
                    'confidence': result['models']['E1_ScamLLM']['score'],
                    'is_phishing': result['models']['E1_ScamLLM']['is_phishing'],
                },
                'e2': {
                    'model': 'E2 (RoBERTa Spam)',
                    'prediction': 'Spam' if result['models']['E2_RoBERTa_Spam']['is_phishing'] else 'Legitimate',
                    'confidence': result['models']['E2_RoBERTa_Spam']['score'],
                    'is_phishing': result['models']['E2_RoBERTa_Spam']['is_phishing'],
                },
                'e3': {
                    'model': 'E3 (AI-Text Detector)',
                    'prediction': 'AI-Generated' if result['models']['E3_AI_Text']['is_ai_generated'] else 'Human',
                    'confidence': result['models']['E3_AI_Text']['score'],
                    'is_phishing': result['models']['E3_AI_Text']['is_ai_generated'],
                },
                'e4': {
                    'model': 'E4 (HTML Analysis)',
                    'prediction': 'Obfuscated' if result['models']['E4_HTML_Analysis']['is_obfuscated'] else 'Clean',
                    'confidence': result['models']['E4_HTML_Analysis']['score'],
                    'is_phishing': result['models']['E4_HTML_Analysis']['is_obfuscated'],
                },
                'features': {
                    'model': 'Email Features + Spoofing',
                    'prediction': 'Phishing' if result['models']['Features']['score'] > 0.5 else 'Legitimate',
                    'confidence': result['models']['Features']['score'],
                    'is_phishing': result['models']['Features']['score'] > 0.5,
                    'spoofing_score': result['models']['Features'].get('spoofing_score', 0),
                },
            },
        }

        if result.get('url_analysis'):
            response['url_analysis'] = result['url_analysis']

        return jsonify(response), 200

    except Exception as e:
        logger.exception("Error in /analyze-email")
        return jsonify({'error': str(e)}), 500


@app.route('/analyze-image', methods=['POST'])
def analyze_image():
    """Analyze image for phishing"""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400

        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        if not allowed_file(file.filename):
            return jsonify({'error': f'Invalid file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            shield = get_image_shield()
            result = shield.predict(filepath)
        finally:
            try:
                os.remove(filepath)
            except Exception:
                pass

        response = {
            'is_phishing': result['is_phishing'],
            'phishing_score': result['phishing_score'],
            'confidence': result['confidence'],
            'risk_factors': result['risk_factors'],
            'latency_ms': result.get('latency_ms', 0),
            'pipeline_scores': result.get('pipeline_scores', {}),
            'pipelines': {
                'qr_detection': {
                    'qr_found': result['pipelines'].get('qr_detection', {}).get('qr_found', False),
                    'qr_count': result['pipelines'].get('qr_detection', {}).get('qr_count', 0),
                    'urls': result['pipelines'].get('qr_detection', {}).get('urls', []),
                    'phishing_urls': result['pipelines'].get('qr_detection', {}).get('phishing_urls', []),
                    'decode_available': result['pipelines'].get('qr_detection', {}).get('decode_available', False),
                },
                'brand_matching': {
                    'brand_detected': result['pipelines'].get('brand_matching', {}).get('brand_detected', False),
                    'top_brand': result['pipelines'].get('brand_matching', {}).get('top_brand', None),
                    'similarity': result['pipelines'].get('brand_matching', {}).get('similarity', 0.0),
                    'brand_phishing_prob': result['pipelines'].get('brand_matching', {}).get('brand_phishing_prob', 0.0),
                    'top5_matches': result['pipelines'].get('brand_matching', {}).get('top5_matches', []),
                },
                'text_extraction': {
                    'text_found': result['pipelines'].get('text_extraction', {}).get('text_found', False),
                    'extracted_text': result['pipelines'].get('text_extraction', {}).get('extracted_text', ''),
                    'text_length': result['pipelines'].get('text_extraction', {}).get('text_length', 0),
                    'text_phishing_prob': result['pipelines'].get('text_extraction', {}).get('text_phishing_prob', 0.0),
                    'sms_verdict': result['pipelines'].get('text_extraction', {}).get('sms_verdict', None),
                },
                'steganography_basic': {
                    'steg_detected': result['pipelines'].get('steganography_basic', {}).get('steg_detected', False),
                    'steg_probability': result['pipelines'].get('steganography_basic', {}).get('steg_probability', 0.0),
                    'indicators': result['pipelines'].get('steganography_basic', {}).get('indicators', []),
                    'chi2_pvalue': result['pipelines'].get('steganography_basic', {}).get('chi2_pvalue', 1.0),
                    'entropy': result['pipelines'].get('steganography_basic', {}).get('entropy', 0.0),
                    'lsb_anomaly': result['pipelines'].get('steganography_basic', {}).get('lsb_anomaly', False),
                },
                'steganography_advanced': {
                    'steg_detected': result['pipelines'].get('steganography_advanced', {}).get('steg_detected', False),
                    'steg_probability': result['pipelines'].get('steganography_advanced', {}).get('steg_probability', 0.0),
                    'steg_type': result['pipelines'].get('steganography_advanced', {}).get('steg_type', None),
                    'confidence': result['pipelines'].get('steganography_advanced', {}).get('confidence', 0.0),
                    'indicators': result['pipelines'].get('steganography_advanced', {}).get('indicators', []),
                    'techniques_triggered': result['pipelines'].get('steganography_advanced', {}).get('techniques_triggered', []),
                },
                'rat_detection': {
                    'rat_detected': result['pipelines'].get('rat_detection', {}).get('rat_detected', False),
                    'rat_probability': result['pipelines'].get('rat_detection', {}).get('rat_probability', 0.0),
                    'detected_rats': result['pipelines'].get('rat_detection', {}).get('detected_families', []),
                    'threat_level': result['pipelines'].get('rat_detection', {}).get('threat_level', 'SAFE'),
                    'indicators': result['pipelines'].get('rat_detection', {}).get('indicators', []),
                    'techniques_triggered': result['pipelines'].get('rat_detection', {}).get('techniques_triggered', []),
                },
            },
        }
        return jsonify(response), 200

    except Exception as e:
        logger.exception("Error in /analyze-image")
        return jsonify({'error': str(e)}), 500


@app.route('/analyze-batch', methods=['POST'])
def analyze_batch():
    """Bulk URL analysis (max 10 URLs)"""
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        if not urls or not isinstance(urls, list):
            return jsonify({'error': 'urls array is required'}), 400
        if len(urls) > 10:
            return jsonify({'error': 'Maximum 10 URLs per batch request'}), 400

        # Normalize URLs
        normalized = []
        for url in urls:
            url = url.strip()
            if url:
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                normalized.append(url)

        if not normalized:
            return jsonify({'error': 'No valid URLs provided'}), 400

        shield = get_url_shield()
        t0 = time.perf_counter()

        # Use ThreadPoolExecutor for parallel URL checks
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(len(normalized), 10)) as pool:
            futures = {url: pool.submit(shield.predict, url) for url in normalized}

        results = []
        for url, fut in futures.items():
            try:
                r = fut.result()
                results.append({
                    'url': url,
                    'is_phishing': r['is_phishing'],
                    'phishing_score': r['phishing_score'],
                    'confidence': r['confidence'],
                    'votes': r['votes'],
                    'latency_ms': r.get('latency_ms', 0),
                })
            except Exception as e:
                results.append({'url': url, 'error': str(e)})

        total_ms = round((time.perf_counter() - t0) * 1000, 1)
        phishing_count = sum(1 for r in results if r.get('is_phishing'))

        return jsonify({
            'total': len(results),
            'phishing_detected': phishing_count,
            'safe': len(results) - phishing_count,
            'total_latency_ms': total_ms,
            'results': results,
        }), 200

    except Exception as e:
        logger.exception("Error in /analyze-batch")
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'version': '2.0 - MILITARY GRADE',
        'shields': {
            'url': _url_shield is not None,
            'sms': _sms_shield is not None,
            'email': _email_shield is not None,
            'image': _image_shield is not None,
        }
    }), 200


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("PHISHING SHIELD 2.0 — WEB SERVER (MILITARY GRADE 2026)")
    print("=" * 80)
    print(f"\nServer starting at: http://localhost:{FLASK_CONFIG['PORT']}")
    print("\nCategories Available:")
    print("  1. URL Phishing Detection    → /analyze        (3 models + features)")
    print("  2. SMS Smishing Detection    → /analyze-sms    (4 models + URL check)")
    print("  3. Email Phishing Detection  → /analyze-email  (4 models + spoofing)")
    print("  4. Image Phishing Detection  → /analyze-image  (6 pipelines - MILITARY GRADE)")
    print("  5. Batch URL Analysis        → /analyze-batch  (up to 10 URLs)")
    print("\nMILITARY-GRADE 2026 THREAT DETECTION:")
    print("  - Advanced Steganography: SRM/RS/SPA/DCT/DWT (12+ algorithms)")
    print("  - RAT Detection: 14 variants (AsyncRAT, QuasarRAT, QuantumRAT, etc.)")
    print("  - Total: 6 parallel pipelines for comprehensive threat analysis")
    print("\nNote: Models load on first request (~10-30 seconds)")
    print("=" * 80 + "\n")
    
    app.run(
        debug=FLASK_CONFIG['DEBUG'],
        host=FLASK_CONFIG['HOST'],
        port=FLASK_CONFIG['PORT'],
        threaded=FLASK_CONFIG['THREADED']
    )
