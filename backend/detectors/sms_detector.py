"""
SMISHING SHIELD — SMS PHISHING DETECTION
Category 2: SMS / Smishing Detection

Architecture:
  S1: SecureBERT (RoBERTa, cybersecurity-tuned, 3-class)  ← NOW ACTIVE
  S3: RoBERTa SMS Spam (primary)
  S4: mDeBERTa-v3 (multilingual, 3-class)                 ← NOW ACTIVE
  S5: RoBERTa Spam Enterprise (secondary)
  Feature Engineering: SMS-specific patterns
  URL Analysis: expand + check any links found

Performance:
  - All 4 models run concurrently via ThreadPoolExecutor
  - URL expansion uses real HTTP HEAD for shorteners
  - torch.no_grad() + FP16 on GPU
  - Tokenizer-level truncation (not char-slice)

Target: >97.5% TPR | <0.8% FPR
"""

import re
import torch
import numpy as np
import requests
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from concurrent.futures import ThreadPoolExecutor
import warnings
import time
import logging

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)

# Shortened-URL service domains
_SHORT_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
    'is.gd', 'buff.ly', 'short.link', 'rebrand.ly', 'cutt.ly',
    'tiny.cc', 'a.co', 'amzn.to', 'youtu.be', 'rb.gy',
}


def _expand_url(url: str, timeout: int = 3) -> str:
    """
    Change #4: Expand shortened URLs via HTTP HEAD request.
    Returns the final destination URL, or the original if expansion fails.
    """
    try:
        parsed_host = re.sub(r'^https?://', '', url).split('/')[0].lower()
        base_host = '.'.join(parsed_host.split('.')[-2:])
        if base_host not in _SHORT_DOMAINS:
            return url
        resp = requests.head(url, allow_redirects=True, timeout=timeout,
                             headers={'User-Agent': 'Mozilla/5.0'})
        return resp.url
    except Exception:
        return url


class SmishingShield:
    """
    SMS Smishing Detection System — 4-model ensemble + feature engineering.
    S1 (SecureBERT) + S3 (RoBERTa SMS) + S4 (mDeBERTa) + S5 (RoBERTa Enterprise)
    """

    def __init__(self):
        print("=" * 80)
        print("SMISHING SHIELD — INITIALIZING (4-MODEL ENSEMBLE)")
        print("=" * 80)
        print("\nArchitecture: SMS Phishing Detection")
        print("  Stage 1: S1 + S3 + S4 + S5 — concurrent ThreadPoolExecutor")
        print("  Stage 2: Feature Engineering (SMS-specific patterns)")
        print("  Stage 3: URL Analysis (expand + URL Shield)")
        print("  Stage 4: Weighted Ensemble Decision\n")

        self._device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"  [Device] Using: {self._device.upper()}")
        self._executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="sms_shield")
        self._load_models()
        self.url_shield = None  # Lazy-loaded

        print("\n[OK] Smishing Shield Ready!")
        print("=" * 80 + "\n")

    # ──────────────────────────────────────────────────────────────────────────
    # Model loading
    # ──────────────────────────────────────────────────────────────────────────
    def _load_models(self):
        """Load all 4 SMS detection models."""

        # S1: SecureBERT (was downloaded but never used — Change #1)
        print("  [1/4] S1 (SecureBERT — RoBERTa cybersecurity-tuned)")
        self.s1_classifier = pipeline(
            "text-classification",
            model="models/sms/S1_SecureBERT",
            device=0 if self._device == "cuda" else -1,
            truncation=True, max_length=512,   # Change #22
        )
        print("        [OK] Loaded (security-specialized RoBERTa)")

        # S3: RoBERTa SMS Spam (existing)
        print("  [2/4] S3 (RoBERTa SMS Spam — primary)")
        self.s3_classifier = pipeline(
            "text-classification",
            model="models/sms/S3_RoBERTa_SMS",
            device=0 if self._device == "cuda" else -1,
            truncation=True, max_length=512,   # Change #22
        )
        print("        [OK] Loaded")

        # S4: mDeBERTa-v3 (was downloaded but never used — Change #2)
        print("  [3/4] S4 (mDeBERTa-v3 — multilingual DeBERTa)")
        self.s4_tokenizer = AutoTokenizer.from_pretrained("models/sms/S4_mDeBERTa")
        self.s4_model = AutoModelForSequenceClassification.from_pretrained("models/sms/S4_mDeBERTa")
        self.s4_model.eval()
        if self._device == "cuda":
            self.s4_model = self.s4_model.half().to("cuda")
        print("        [OK] Loaded (multilingual smishing detection)")

        # S5: RoBERTa Spam Enterprise (existing)
        print("  [4/4] S5 (RoBERTa Enterprise Spam)")
        self.s5_classifier = pipeline(
            "text-classification",
            model="models/sms/S5_RoBERTa_Spam",
            device=0 if self._device == "cuda" else -1,
            truncation=True, max_length=512,   # Change #22
        )
        print("        [OK] Loaded")

    # ──────────────────────────────────────────────────────────────────────────
    # URL extraction + expansion
    # ──────────────────────────────────────────────────────────────────────────
    def extract_urls_from_text(self, text: str) -> list:
        """Extract and expand all URLs found in SMS text."""
        url_pattern = (
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|'
            r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            r'|(?:www\.|bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|rb\.gy)[^\s]+'
            r'|\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|co|io|app|dev|xyz|tk|ml|ga|cf|online|site|ly|info|biz)\b(?:/[^\s]*)?'
        )
        raw_urls = re.findall(url_pattern, text, re.IGNORECASE)

        cleaned = []
        for url in raw_urls:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            expanded = _expand_url(url)  # Change #4
            cleaned.append(expanded)
        return cleaned

    # ──────────────────────────────────────────────────────────────────────────
    # Feature engineering
    # ──────────────────────────────────────────────────────────────────────────
    def extract_sms_features(self, text: str) -> dict:
        features = {}
        text_lower = text.lower()

        features['length'] = len(text)
        features['word_count'] = len(text.split())
        features['has_url'] = 1 if re.search(r'http[s]?://|bit\.ly|tinyurl|rb\.gy', text_lower) else 0
        features['has_phone'] = 1 if re.search(r'\d{3}[-.\\s]?\d{3}[-.\\s]?\d{4}', text) else 0

        urgency_words = ['urgent', 'immediate', 'now', 'asap', 'expire', 'limited', 'act now', 'hurry', 'last chance']
        features['urgency_count'] = sum(1 for w in urgency_words if w in text_lower)

        financial_words = ['$', 'free', 'win', 'winner', 'prize', 'cash', 'money', 'credit', 'bank', 'account', 'reward']
        features['financial_count'] = sum(1 for w in financial_words if w in text_lower)

        brands = ['paypal', 'amazon', 'usps', 'fedex', 'dhl', 'irs', 'bank', 'apple', 'google', 'microsoft', 'netflix']
        features['brand_mention'] = sum(1 for b in brands if b in text_lower)

        security_words = ['verify', 'confirm', 'suspend', 'locked', 'security', 'update', 'validate', 'otp', 'pin']
        features['security_count'] = sum(1 for w in security_words if w in text_lower)

        features['has_click_here'] = 1 if 'click here' in text_lower or 'click now' in text_lower else 0
        features['has_reply'] = 1 if 'reply' in text_lower or 'text back' in text_lower else 0
        features['all_caps_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')

        features['has_shortened_url'] = 1 if re.search(
            r'bit\.ly|tinyurl|goo\.gl|ow\.ly|t\.co|rb\.gy|cutt\.ly', text_lower) else 0

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', '.link']
        features['suspicious_tld'] = 1 if any(tld in text_lower for tld in suspicious_tlds) else 0

        return features

    def _calculate_feature_score(self, features: dict) -> float:
        risk = 0
        risk += features['has_url'] * 3
        risk += features['has_shortened_url'] * 5
        risk += features['suspicious_tld'] * 4
        risk += features['urgency_count'] * 2
        risk += features['financial_count'] * 2
        risk += features['security_count'] * 3
        risk += features['brand_mention'] * 2
        risk += features['has_click_here'] * 3
        risk += features['has_phone'] * 1
        risk += features['has_reply'] * 1
        risk += min(features['exclamation_count'], 3) * 0.5
        if features['all_caps_ratio'] > 0.5:
            risk += 2
        return min(risk / 20.0, 1.0)

    # ──────────────────────────────────────────────────────────────────────────
    # Individual model predictions
    # ──────────────────────────────────────────────────────────────────────────
    def _predict_s1(self, text: str):
        """S1: SecureBERT — 3-class (LABEL_0 / LABEL_1 / LABEL_2)."""
        result = self.s1_classifier(text)[0]
        # Treat LABEL_1 or LABEL_2 as suspicious/phishing
        is_spam = result['label'].lower() in ('label_1', 'label_2') or 'spam' in result['label'].lower()
        score = result['score'] if is_spam else (1 - result['score'])
        return {'is_spam': is_spam, 'score': float(score), 'label': result['label']}

    def _predict_s3(self, text: str):
        """S3: RoBERTa SMS Spam."""
        result = self.s3_classifier(text)[0]
        is_spam = 'spam' in result['label'].lower() or 'label_1' in result['label'].lower()
        score = result['score'] if is_spam else (1 - result['score'])
        return {'is_spam': is_spam, 'score': float(score), 'label': result['label']}

    def _predict_s4(self, text: str):
        """S4: mDeBERTa-v3 — multilingual 3-class (Change #2)."""
        # Change #22: tokenizer-level truncation
        inputs = self.s4_tokenizer(
            text, return_tensors="pt", truncation=True,
            max_length=512, padding=True
        )
        if self._device == "cuda":
            inputs = {k: v.to("cuda") for k, v in inputs.items()}
        with torch.no_grad():
            outputs = self.s4_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)[0].float().cpu().numpy()

        pred_idx = int(np.argmax(probs))
        # 3-class: index 0 = legit, 1+2 = spam/phishing
        is_spam = pred_idx > 0
        spam_prob = float(probs[1]) + float(probs[2]) if len(probs) > 2 else float(probs[1])
        return {'is_spam': is_spam, 'score': spam_prob, 'label': f'LABEL_{pred_idx}'}

    def _predict_s5(self, text: str):
        """S5: RoBERTa Enterprise Spam."""
        result = self.s5_classifier(text)[0]
        is_spam = 'spam' in result['label'].lower() or 'label_1' in result['label'].lower()
        score = result['score'] if is_spam else (1 - result['score'])
        return {'is_spam': is_spam, 'score': float(score), 'label': result['label']}

    # ──────────────────────────────────────────────────────────────────────────
    # Main prediction
    # ──────────────────────────────────────────────────────────────────────────
    def predict(self, sms_text: str) -> dict:
        """
        Predict if SMS is smishing.
        Change #1,2: Uses all 4 models (S1 + S3 + S4 + S5).
        Change #3: Rebalanced ensemble weights.
        Change #4: Actual URL expansion for shorteners.
        Change #19: Parallel model execution.
        """
        t0 = time.perf_counter()

        # ── Stage 1: Run 4 models in parallel (Change #19) ────────────────────
        futures = {
            's1': self._executor.submit(self._predict_s1, sms_text),
            's3': self._executor.submit(self._predict_s3, sms_text),
            's4': self._executor.submit(self._predict_s4, sms_text),
            's5': self._executor.submit(self._predict_s5, sms_text),
            'feat': self._executor.submit(self.extract_sms_features, sms_text),
        }

        s1_r = futures['s1'].result()
        s3_r = futures['s3'].result()
        s4_r = futures['s4'].result()
        s5_r = futures['s5'].result()
        features = futures['feat'].result()
        feature_score = self._calculate_feature_score(features)

        # ── Stage 2: URL extraction + expansion + URL Shield ──────────────────
        urls_in_sms = self.extract_urls_from_text(sms_text)
        url_analysis = []
        url_phishing_detected = False

        if urls_in_sms:
            try:
                if self.url_shield is None:
                    from backend.detectors.url_detector import PhishingShield2
                    self.url_shield = PhishingShield2()
                # Check expanded URLs in parallel
                url_futures = {
                    url: self._executor.submit(self.url_shield.predict, url)
                    for url in urls_in_sms
                }
                for url, fut in url_futures.items():
                    url_result = fut.result()
                    url_analysis.append({
                        'url': url,
                        'is_phishing': url_result['is_phishing'],
                        'score': url_result['phishing_score'],
                        'confidence': url_result['confidence'],
                    })
                    if url_result['is_phishing']:
                        url_phishing_detected = True
            except Exception as e:
                logger.warning(f"URL analysis failed: {e}")

        # ── Stage 3: Rebalanced ensemble (Change #3) ─────────────────────────
        if url_phishing_detected:
            avg_url_score = sum(u['score'] for u in url_analysis) / len(url_analysis)
            # With URL signal: URL gets highest weight
            ensemble_score = (
                0.15 * s1_r['score'] +
                0.20 * s3_r['score'] +
                0.15 * s4_r['score'] +
                0.20 * s5_r['score'] +
                0.05 * feature_score +
                0.25 * avg_url_score
            )
            votes = sum([s1_r['is_spam'], s3_r['is_spam'], s4_r['is_spam'],
                         s5_r['is_spam'], feature_score > 0.5, url_phishing_detected])
            total_votes = 6
        else:
            # Without URL: balance the 4 models + features
            # Change #3: new weights (was s3=0.40, s5=0.35, feats=0.25 — only 2 models)
            ensemble_score = (
                0.20 * s1_r['score'] +
                0.25 * s3_r['score'] +
                0.20 * s4_r['score'] +
                0.25 * s5_r['score'] +
                0.10 * feature_score
            )
            votes = sum([s1_r['is_spam'], s3_r['is_spam'], s4_r['is_spam'],
                         s5_r['is_spam'], feature_score > 0.5])
            total_votes = 5

        # ── Stage 4: Final decision ────────────────────────────────────────────
        if url_phishing_detected:
            is_smishing = True
        else:
            is_smishing = (ensemble_score > 0.55) and (votes >= 2)
            if ensemble_score > 0.85 or votes >= total_votes:
                is_smishing = True
            if ensemble_score < 0.15 and votes == 0:
                is_smishing = False

        confidence = max(ensemble_score, 1 - ensemble_score)
        latency_ms = (time.perf_counter() - t0) * 1000

        result = {
            'text': sms_text,
            'is_smishing': bool(is_smishing),
            'smishing_score': float(ensemble_score),
            'confidence': float(confidence),
            'votes': f"{votes}/{total_votes}",
            'category': 'Smishing' if is_smishing else 'Legitimate',
            'latency_ms': round(latency_ms, 1),
            'models': {
                'S1_SecureBERT': {
                    'prediction': 'Spam' if s1_r['is_spam'] else 'Ham',
                    'confidence': float(s1_r['score']),
                    'smishing_prob': float(s1_r['score']),
                },
                'S3_RoBERTa_SMS': {
                    'prediction': 'Spam' if s3_r['is_spam'] else 'Ham',
                    'confidence': float(s3_r['score']),
                    'smishing_prob': float(s3_r['score']),
                },
                'S4_mDeBERTa': {
                    'prediction': 'Spam' if s4_r['is_spam'] else 'Ham',
                    'confidence': float(s4_r['score']),
                    'smishing_prob': float(s4_r['score']),
                },
                'S5_RoBERTa_Enterprise': {
                    'prediction': 'Spam' if s5_r['is_spam'] else 'Ham',
                    'confidence': float(s5_r['score']),
                    'smishing_prob': float(s5_r['score']),
                },
                'Features': {
                    'score': float(feature_score),
                    'risk_indicators': {
                        'has_url': bool(features['has_url']),
                        'has_shortened_url': bool(features['has_shortened_url']),
                        'urgency_keywords': int(features['urgency_count']),
                        'financial_keywords': int(features['financial_count']),
                        'brand_mention': int(features['brand_mention']),
                        'security_keywords': int(features['security_count']),
                    },
                },
            },
        }

        if url_analysis:
            result['url_analysis'] = url_analysis
            result['urls_found'] = len(url_analysis)
            result['phishing_urls_detected'] = sum(1 for u in url_analysis if u['is_phishing'])

        return result

    def analyze(self, sms_text: str, verbose: bool = True) -> dict:
        if verbose:
            print(f"\n{'=' * 80}")
            print("SMISHING SHIELD — ANALYSIS")
            print(f"{'=' * 80}")
            print(f"SMS: {sms_text}\n")

        result = self.predict(sms_text)

        if verbose:
            print("Stage 1: Deep Learning Models (parallel)")
            for key in ['S1_SecureBERT', 'S3_RoBERTa_SMS', 'S4_mDeBERTa', 'S5_RoBERTa_Enterprise']:
                m = result['models'][key]
                print(f"  {key:<25} {m['prediction']:<6} "
                      f"Smishing: {m['smishing_prob']:.2%}")
            print(f"\nStage 2: Feature Score: {result['models']['Features']['score']:.2%}")
            if 'url_analysis' in result:
                print(f"\nStage 3: URLs: {result['urls_found']} found, "
                      f"{result['phishing_urls_detected']} phishing")
            print(f"\nEnsemble: {result['smishing_score']:.2%} | Votes: {result['votes']}")
            print(f"Latency: {result['latency_ms']}ms")
            verdict = "[!] SMISHING DETECTED" if result['is_smishing'] else "[OK] LEGITIMATE"
            print(f"Verdict: {verdict}")
            print(f"{'=' * 80}\n")

        return result

    def __del__(self):
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)


if __name__ == "__main__":
    shield = SmishingShield()
    tests = [
        "Hi mom, I'll be home late today.",
        "WINNER! Free iPhone! Click: bit.ly/win-now",
        "URGENT: PayPal account suspended. Verify: http://paypal-secure-verify.xyz/login",
        "Your Amazon order shipped. Track: https://www.amazon.com/track",
    ]
    for msg in tests:
        shield.analyze(msg)
