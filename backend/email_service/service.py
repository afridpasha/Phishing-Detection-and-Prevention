import re
import time
from typing import Dict, List, Optional

from backend.api_gateway.config import settings
from backend.email_service.attachment.cape_client import CAPEClient
from backend.email_service.attachment.viper_monkey import ViperMonkeyAnalyzer
from backend.email_service.attachment.yara_scanner import YARAScanner
from backend.email_service.behavior_graph.bec_detector import BECDetector
from backend.email_service.models.ai_text_detector import AITextDetector
from backend.email_service.models.codebert_model import CodeBERTHTMLDetector
from backend.email_service.models.phishbert_model import PhishBERTClassifier
from backend.email_service.parser.header_analyzer import HeaderAnalyzer
from backend.email_service.parser.html_deobfuscator import HTMLDeobfuscator

phishbert_model = None
ai_text_detector = None
gat_model = None
codebert_model = None
header_analyzer = None
html_deobfuscator = None
yara_scanner = None
macro_analyzer = None
cape_client = None


async def load_email_models():
    global phishbert_model, ai_text_detector, gat_model, codebert_model
    global header_analyzer, html_deobfuscator, yara_scanner, macro_analyzer, cape_client

    device = 'cuda' if settings.ENABLE_GPU else 'cpu'
    base = settings.MODELS_BASE_PATH

    phishbert_model = PhishBERTClassifier(f'{base}/email/phishbert_email', device)
    ai_text_detector = AITextDetector(f'{base}/email/ai_text_detector', device)
    gat_model = BECDetector(f'{base}/email/gat_bec.pt')
    codebert_model = CodeBERTHTMLDetector(f'{base}/email/codebert_html', device)

    header_analyzer = HeaderAnalyzer()
    html_deobfuscator = HTMLDeobfuscator()
    yara_scanner = YARAScanner()
    macro_analyzer = ViperMonkeyAnalyzer()
    cape_client = CAPEClient()


def get_email_model_status() -> Dict[str, bool]:
    return {
        'phishbert': phishbert_model is not None,
        'ai_text_detector': ai_text_detector is not None,
        'gat_bec': gat_model is not None,
        'codebert_html': codebert_model is not None,
    }


async def analyze_email(subject: str, body_text: str, body_html: Optional[str], sender_email: str, sender_display_name: Optional[str], recipient_email: Optional[str], headers_raw: Optional[str], attachments: Optional[List]) -> Dict:
    start = time.time()

    header = header_analyzer.analyze(headers_raw or '', sender_email, sender_display_name) if header_analyzer else {}
    html_info = html_deobfuscator.extract_indicators(body_html) if html_deobfuscator else {'urls': []}

    phish_score = phishbert_model.predict(subject, body_text) if phishbert_model else 0.5
    ai_score = ai_text_detector.predict(body_text) if ai_text_detector else 0.5
    codebert_score = codebert_model.predict(body_html) if codebert_model else 0.5

    bec_features = {
        'cold_contact_flag': 1.0 if recipient_email else 0.0,
        'display_name_mismatch_flag': 1.0 if header.get('display_name_mismatch') else 0.0,
        'reply_to_mismatch_flag': 1.0 if header.get('reply_to_mismatch') else 0.0,
        'financial_keywords_ratio': _financial_ratio(subject + ' ' + body_text),
    }
    bec_score = gat_model.predict(bec_features) if gat_model else 0.5

    attachment_results = []
    for item in attachments or []:
        filename = item.get('filename', 'unknown') if isinstance(item, dict) else getattr(item, 'filename', 'unknown')
        content_b64 = item.get('content_b64', '') if isinstance(item, dict) else getattr(item, 'content_b64', '')

        yara_result = yara_scanner.scan_b64(content_b64) if yara_scanner else {'malicious': False, 'matches': []}
        macro_result = macro_analyzer.analyze_b64(content_b64, filename) if macro_analyzer else {'has_macro': False}
        cape_result = await cape_client.submit_file(filename, content_b64) if cape_client else {'verdict': 'unknown'}

        verdict = 'benign'
        malware_family = None
        if yara_result.get('malicious') or macro_result.get('has_macro'):
            verdict = 'malicious'
            malware_family = 'suspicious_macro_or_binary'
        elif cape_result.get('verdict') in {'submitted', 'malicious'}:
            verdict = 'suspicious'

        attachment_results.append({'filename': filename, 'verdict': verdict, 'malware_family': malware_family})

    model_scores = {
        'phishbert': float(phish_score),
        'ai_text_detector': float(ai_score),
        'gat_bec': float(bec_score),
        'codebert_html': float(codebert_score),
    }

    urls_found = sorted(set(re.findall(r'https?://[^\s]+', body_text) + html_info.get('urls', [])))

    indicators = []
    if header.get('spf_result') == 'fail':
        indicators.append('SPF failed')
    if header.get('dkim_result') == 'fail':
        indicators.append('DKIM failed')
    if header.get('dmarc_result') == 'fail':
        indicators.append('DMARC failed')
    if header.get('display_name_mismatch'):
        indicators.append('Display name mismatch')
    if any(a['verdict'] == 'malicious' for a in attachment_results):
        indicators.append('Malicious attachment indicators found')

    return {
        'model_scores': model_scores,
        'final_score': sum(model_scores.values()) / len(model_scores),
        'indicators': indicators,
        'metadata': {
            'spf_result': header.get('spf_result', 'none'),
            'dkim_result': header.get('dkim_result', 'none'),
            'dmarc_result': header.get('dmarc_result', 'none'),
            'display_name_mismatch': bool(header.get('display_name_mismatch', False)),
            'is_ai_generated': ai_score >= 0.5,
            'ai_generated_probability': float(ai_score),
            'attachment_results': attachment_results,
            'bec_risk': float(bec_score),
            'urls_found': urls_found,
        },
        'latency_ms': (time.time() - start) * 1000,
    }


def _financial_ratio(text: str) -> float:
    lower = text.lower()
    keywords = ['wire transfer', 'invoice', 'payment', 'iban', 'urgent', 'confidential']
    hits = sum(1 for k in keywords if k in lower)
    return min(1.0, hits / max(1, len(keywords)))
