"""
PHISHING SHIELD 2.0 - URL PHISHING DETECTION
Category 1: URL Phishing Detection

Architecture:
  Stage 1: Deep Learning Models (U1, U2, U4) — run in PARALLEL
  Stage 2: Feature Engineering (87 + typosquatting + domain-age features)
  Stage 3: Meta-Ensemble (weighted voting)
  Stage 4: Final Decision

Performance:
  - Models run concurrently via ThreadPoolExecutor
  - Results cached with TTL to avoid redundant inference
  - FP16 half-precision on GPU
  - torch.no_grad() enforced everywhere

Target: >97.5% TPR | <0.8% FPR
"""

import torch
import numpy as np
import onnxruntime
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from functools import lru_cache
import warnings
import threading
import time
import logging

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)

# ─── Optional: cachetools for TTL cache ──────────────────────────────────────
try:
    from cachetools import TTLCache
    _url_cache = TTLCache(maxsize=1000, ttl=3600)
    _cache_lock = threading.Lock()
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    _url_cache = {}
    _cache_lock = threading.Lock()

# ─── Optional: python-whois for domain age ───────────────────────────────────
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed. Domain age detection disabled.")

# Top brands for typosquatting detection
_BRANDS = [
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
    'netflix', 'ebay', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank',
    'irs', 'usps', 'fedex', 'dhl', 'ups', 'adobe', 'zoom',
    'spotify', 'youtube', 'binance', 'coinbase', 'robinhood',
]


def _get_typosquatting_score(domain: str) -> float:
    """
    Compute how similar domain is to any known brand.
    Returns highest similarity score (0–1). Score > 0.75 is suspicious.
    Uses SequenceMatcher (pure stdlib, no extra deps).
    """
    domain_clean = re.sub(r'\.[a-z]{2,6}$', '', domain.lower())
    domain_clean = re.sub(r'[-_0-9]', '', domain_clean)
    if not domain_clean:
        return 0.0
    best = 0.0
    for brand in _BRANDS:
        ratio = SequenceMatcher(None, domain_clean, brand).ratio()
        if ratio > best:
            best = ratio
    return best


def _get_domain_age_days(domain: str) -> int:
    """
    Returns domain age in days using WHOIS.
    Returns -1 if WHOIS failed or package unavailable.
    """
    if not WHOIS_AVAILABLE:
        return -1
    try:
        w = python_whois.query(domain, timeout=3)
        if w and w.creation_date:
            from datetime import datetime
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            age = (datetime.now() - cd).days
            return max(age, 0)
    except Exception:
        pass
    return -1


class PhishingShield2:
    """
    URL Phishing Shield 2.0
    Multi-stage ensemble: U1 (BERT-base) + U2 (BERT-large) + U4 (LinearSVM ONNX)
    + Feature Engineering (typosquatting, domain age, 87 URL features)
    """

    def __init__(self):
        print("=" * 80)
        print("PHISHING SHIELD 2.0 - INITIALIZING")
        print("=" * 80)
        print("\nArchitecture: Multi-Stage Ensemble (Parallel Inference)")
        print("  Stage 1: U1 + U2 + U4 — concurrent ThreadPoolExecutor")
        print("  Stage 2: Feature Engineering (87 + typosquatting + domain-age)")
        print("  Stage 3: Weighted Meta-Ensemble")
        print("  Stage 4: Final Decision Logic\n")

        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="url_shield")
        self._load_models()

        print("\n[OK] Phishing Shield 2.0 Ready!")
        print("=" * 80 + "\n")

    # ──────────────────────────────────────────────────────────────────────────
    # Model loading
    # ──────────────────────────────────────────────────────────────────────────
    def _load_models(self):
        """Load all pre-trained models with FP16 if GPU available."""
        self._device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"  [Device] Using: {self._device.upper()}")

        # U1: BERT-base 4-class (URLNet role)
        print("  [1/3] U1 (BERT-base 4-class) — URLNet role")
        self.u1_tokenizer = AutoTokenizer.from_pretrained("models/url/U1")
        self.u1_model = AutoModelForSequenceClassification.from_pretrained("models/url/U1")
        self.u1_model.eval()
        if self._device == "cuda":
            self.u1_model = self.u1_model.half().to("cuda")
        self.u1_labels = ["Benign", "Defacement", "Phishing", "Malware"]
        print("        [OK] Loaded")

        # U2: BERT-large binary (DeBERTa role)
        print("  [2/3] U2 (BERT-large binary) — DeBERTa role")
        self.u2_tokenizer = AutoTokenizer.from_pretrained("models/url/U2")
        self.u2_model = AutoModelForSequenceClassification.from_pretrained("models/url/U2")
        self.u2_model.eval()
        if self._device == "cuda":
            self.u2_model = self.u2_model.half().to("cuda")
        print("        [OK] Loaded")

        # U4: LinearSVM ONNX (XGBoost role)
        print("  [3/3] U4 (LinearSVM ONNX) — XGBoost role")
        providers = (
            ["CUDAExecutionProvider", "CPUExecutionProvider"]
            if self._device == "cuda" else ["CPUExecutionProvider"]
        )
        self.u4_session = onnxruntime.InferenceSession(
            "models/url/U4/model.onnx", providers=providers
        )
        print("        [OK] Loaded")
        print("\n  [!] U3 (DeBERTa-v3) — disabled (untrained weights)")

    # ──────────────────────────────────────────────────────────────────────────
    # Feature engineering
    # ──────────────────────────────────────────────────────────────────────────
    def extract_url_features(self, url: str) -> dict:
        """Extract 87+ features from URL, including typosquatting and domain age."""
        features = {}
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path

            # 1-10: Length features
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(path)
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_questionmarks'] = url.count('?')
            features['num_equals'] = url.count('=')
            features['num_at'] = url.count('@')

            # 11-20: Character features
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['num_letters'] = sum(c.isalpha() for c in url)
            features['digit_ratio'] = features['num_digits'] / max(len(url), 1)
            features['letter_ratio'] = features['num_letters'] / max(len(url), 1)
            features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
            features['has_port'] = 1 if ':' in domain and any(c.isdigit() for c in domain.split(':')[-1]) else 0
            features['num_subdomains'] = domain.count('.') - 1 if domain.count('.') > 0 else 0
            features['is_https'] = 1 if url.startswith('https://') else 0
            features['url_entropy'] = self._calculate_entropy(url)
            features['domain_entropy'] = self._calculate_entropy(domain)

            # 21-30: Suspicious patterns
            features['has_login'] = 1 if 'login' in url.lower() else 0
            features['has_signin'] = 1 if 'signin' in url.lower() else 0
            features['has_verify'] = 1 if 'verify' in url.lower() else 0
            features['has_account'] = 1 if 'account' in url.lower() else 0
            features['has_update'] = 1 if 'update' in url.lower() else 0
            features['has_secure'] = 1 if 'secure' in url.lower() else 0
            features['has_banking'] = 1 if 'bank' in url.lower() else 0
            features['has_confirm'] = 1 if 'confirm' in url.lower() else 0
            features['has_suspend'] = 1 if 'suspend' in url.lower() else 0
            features['has_alert'] = 1 if 'alert' in url.lower() else 0

            # 31-40: Brand keywords in URL
            brands_kw = ['paypal', 'amazon', 'microsoft', 'apple', 'google',
                         'facebook', 'netflix', 'ebay', 'wells', 'chase']
            for brand in brands_kw:
                features[f'has_{brand}'] = 1 if brand in url.lower() else 0

            # 41-50: Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top',
                                '.work', '.click', '.link', '.loan']
            for i, tld in enumerate(suspicious_tlds):
                features[f'tld_{i}'] = 1 if url.endswith(tld) else 0

            # 51-60: Special character patterns
            features['consecutive_dots'] = 1 if '..' in url else 0
            features['consecutive_hyphens'] = 1 if '--' in url else 0
            features['starts_with_digit'] = 1 if domain and domain[0].isdigit() else 0
            features['has_hex'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
            features['has_unicode'] = 1 if any(ord(c) > 127 for c in url) else 0
            features['has_punycode'] = 1 if 'xn--' in url else 0
            features['path_depth'] = path.count('/')
            features['query_length'] = len(parsed.query)
            features['fragment_length'] = len(parsed.fragment)
            features['has_redirect'] = 1 if 'redirect' in url.lower() or 'url=' in url.lower() else 0

            # 61-70: Domain structural features
            features['domain_has_digit'] = 1 if any(c.isdigit() for c in domain) else 0
            features['domain_has_hyphen'] = 1 if '-' in domain else 0
            features['domain_token_count'] = len(re.findall(r'[a-zA-Z]+', domain))
            tokens = re.findall(r'[a-zA-Z]+', domain)
            features['longest_token'] = max([len(t) for t in tokens], default=0)
            features['shortest_token'] = min([len(t) for t in tokens], default=0)
            features['avg_token_length'] = float(np.mean([len(t) for t in tokens])) if tokens else 0.0
            features['vowel_ratio'] = sum(c.lower() in 'aeiou' for c in domain) / max(len(domain), 1)
            features['consonant_ratio'] = sum(c.lower() in 'bcdfghjklmnpqrstvwxyz' for c in domain) / max(len(domain), 1)
            features['digit_letter_ratio'] = features['num_digits'] / max(features['num_letters'], 1)
            features['special_char_ratio'] = (len(url) - features['num_digits'] - features['num_letters']) / max(len(url), 1)

            # 71-80: Path features
            features['path_has_extension'] = 1 if re.search(r'\.[a-z]{2,4}$', path) else 0
            features['path_has_php'] = 1 if '.php' in path else 0
            features['path_has_html'] = 1 if '.html' in path or '.htm' in path else 0
            features['path_has_asp'] = 1 if '.asp' in path else 0
            features['path_has_exe'] = 1 if '.exe' in path else 0
            features['path_has_zip'] = 1 if '.zip' in path else 0
            features['path_has_script'] = 1 if 'script' in path.lower() else 0
            features['path_has_admin'] = 1 if 'admin' in path.lower() else 0
            features['path_has_config'] = 1 if 'config' in path.lower() else 0
            features['path_has_backup'] = 1 if 'backup' in path.lower() or 'bak' in path.lower() else 0

            # 81-87: Composite risk scores
            features['url_complexity'] = features['url_length'] * features['url_entropy']
            features['domain_complexity'] = features['domain_length'] * features['domain_entropy']
            features['suspicious_keyword_count'] = sum([
                features['has_login'], features['has_verify'], features['has_secure'],
                features['has_account'], features['has_update'], features['has_banking']
            ])
            features['brand_keyword_count'] = sum([features.get(f'has_{b}', 0) for b in brands_kw])
            features['suspicious_tld_match'] = sum([features.get(f'tld_{i}', 0) for i in range(len(suspicious_tlds))])
            features['risk_score'] = (
                features['suspicious_keyword_count'] * 2 +
                features['brand_keyword_count'] * 1.5 +
                features['suspicious_tld_match'] * 3 +
                features['has_ip'] * 5
            )
            features['legitimacy_score'] = (
                features['is_https'] * 2 +
                (1 if features['domain_length'] > 5 else 0) +
                (1 if features['num_subdomains'] <= 2 else 0)
            )

            # ── NEW: Typosquatting score (Change #15) ──────────────────────
            typo_score = _get_typosquatting_score(domain)
            features['typosquatting_score'] = typo_score
            features['is_typosquat'] = 1 if typo_score > 0.75 else 0

            # ── NEW: Domain age detection (Change #16) ─────────────────────
            age_days = _get_domain_age_days(domain)
            features['domain_age_days'] = age_days if age_days >= 0 else 365
            features['is_new_domain'] = 1 if 0 <= age_days <= 30 else 0

        except Exception as e:
            logger.warning(f"Feature extraction error: {e}")
            features = {f'feature_{i}': 0 for i in range(91)}

        return features

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob if p > 0)

    # ──────────────────────────────────────────────────────────────────────────
    # Individual model predictions
    # ──────────────────────────────────────────────────────────────────────────
    def _predict_u1(self, url: str) -> dict:
        """U1: BERT-base 4-class."""
        # Change #22: tokenizer-level truncation, not char slice
        inputs = self.u1_tokenizer(
            url, return_tensors="pt", truncation=True,
            padding=True, max_length=128
        )
        if self._device == "cuda":
            inputs = {k: v.to("cuda") for k, v in inputs.items()}
        with torch.no_grad():
            outputs = self.u1_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)[0].float().cpu().numpy()

        pred_idx = int(np.argmax(probs))
        phishing_prob = float(probs[2] + probs[3] + probs[1])  # Phishing + Malware + Defacement

        return {
            'prediction': self.u1_labels[pred_idx],
            'confidence': float(probs[pred_idx]),
            'phishing_prob': phishing_prob,
            'is_phishing': self.u1_labels[pred_idx] in ['Phishing', 'Malware', 'Defacement'],
        }

    def _predict_u2(self, url: str) -> dict:
        """U2: BERT-large binary."""
        inputs = self.u2_tokenizer(
            url, return_tensors="pt", truncation=True,
            padding=True, max_length=128
        )
        if self._device == "cuda":
            inputs = {k: v.to("cuda") for k, v in inputs.items()}
        with torch.no_grad():
            outputs = self.u2_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)[0].float().cpu().numpy()

        pred_idx = int(np.argmax(probs))
        return {
            'prediction': 'Phishing' if pred_idx == 1 else 'Benign',
            'confidence': float(probs[pred_idx]),
            'phishing_prob': float(probs[1]),
            'is_phishing': pred_idx == 1,
        }

    def _predict_u4(self, url: str) -> dict:
        """U4: LinearSVM ONNX."""
        inputs = np.array([url], dtype="str")
        results = self.u4_session.run(None, {"inputs": inputs})
        probs = results[1][0]
        pred_idx = int(np.argmax(probs))
        return {
            'prediction': 'Phishing' if pred_idx == 1 else 'Benign',
            'confidence': float(probs[pred_idx]),
            'phishing_prob': float(probs[1]),
            'is_phishing': pred_idx == 1,
        }

    def _calculate_feature_score(self, features: dict) -> float:
        """Derive phishing probability from engineered features."""
        risk = features.get('risk_score', 0)
        legitimacy = features.get('legitimacy_score', 0)

        score = (risk - legitimacy + 10) / 20

        # Boost for typosquatting and new domains
        if features.get('is_typosquat'):
            score = min(score + 0.20, 1.0)
        if features.get('is_new_domain'):
            score = min(score + 0.15, 1.0)

        return max(0.0, min(1.0, score))

    # ──────────────────────────────────────────────────────────────────────────
    # Main prediction — with caching + parallel execution
    # ──────────────────────────────────────────────────────────────────────────
    def predict(self, url: str) -> dict:
        """
        Main prediction method.
        Change #17: TTL-cached results (1 hour).
        Change #19: Models run in parallel via ThreadPoolExecutor.
        """
        # ── Cache check ──────────────────────────────────────────────────────
        if CACHE_AVAILABLE:
            with _cache_lock:
                if url in _url_cache:
                    return _url_cache[url]

        t0 = time.perf_counter()

        # ── Stage 1 & 2: Run all 4 tasks in parallel (Change #19) ───────────
        futures = {}
        futures['u1'] = self._executor.submit(self._predict_u1, url)
        futures['u2'] = self._executor.submit(self._predict_u2, url)
        futures['u4'] = self._executor.submit(self._predict_u4, url)
        futures['feat'] = self._executor.submit(self.extract_url_features, url)

        u1_result = futures['u1'].result()
        u2_result = futures['u2'].result()
        u4_result = futures['u4'].result()
        features = futures['feat'].result()

        feature_score = self._calculate_feature_score(features)

        # ── Stage 3: Weighted meta-ensemble ──────────────────────────────────
        weights = {'u1': 0.30, 'u2': 0.30, 'u4': 0.20, 'features': 0.20}

        ensemble_score = (
            weights['u1'] * u1_result['phishing_prob'] +
            weights['u2'] * u2_result['phishing_prob'] +
            weights['u4'] * u4_result['phishing_prob'] +
            weights['features'] * feature_score
        )

        votes = sum([
            u1_result['is_phishing'],
            u2_result['is_phishing'],
            u4_result['is_phishing'],
            feature_score > 0.5,
        ])

        # ── Stage 4: Final decision ───────────────────────────────────────────
        is_phishing = (ensemble_score > 0.55) and (votes >= 2)
        if ensemble_score > 0.85 or votes >= 3:
            is_phishing = True
        if ensemble_score < 0.15 and votes == 0:
            is_phishing = False

        # Typosquatting / new-domain override
        if features.get('is_typosquat') and features.get('brand_keyword_count', 0) > 0:
            is_phishing = True

        confidence = max(ensemble_score, 1 - ensemble_score)
        latency_ms = (time.perf_counter() - t0) * 1000

        result = {
            'url': url,
            'is_phishing': bool(is_phishing),
            'phishing_score': float(ensemble_score),
            'confidence': float(confidence),
            'votes': f"{votes}/4",
            'latency_ms': round(latency_ms, 1),
            'tpr_target': '>97.5%',
            'fpr_target': '<0.8%',
            'models': {
                'U1_URLNet': u1_result,
                'U2_DeBERTa': u2_result,
                'U4_XGBoost': u4_result,
                'Features': {
                    'score': float(feature_score),
                    'risk_score': float(features.get('risk_score', 0)),
                    'legitimacy_score': float(features.get('legitimacy_score', 0)),
                    'typosquatting_score': float(features.get('typosquatting_score', 0)),
                    'is_new_domain': bool(features.get('is_new_domain', False)),
                    'domain_age_days': int(features.get('domain_age_days', -1)),
                },
            },
        }

        # Cache it
        if CACHE_AVAILABLE:
            with _cache_lock:
                _url_cache[url] = result

        return result

    def analyze(self, url: str, verbose: bool = True) -> dict:
        """Detailed analysis with console output."""
        if verbose:
            print(f"\n{'=' * 80}")
            print("PHISHING SHIELD 2.0 — URL ANALYSIS")
            print(f"{'=' * 80}")
            print(f"URL: {url}\n")

        result = self.predict(url)

        if verbose:
            print("Stage 1: Deep Learning Models (parallel)")
            print(f"  U1 (URLNet):   {result['models']['U1_URLNet']['prediction']:<12} "
                  f"Phishing: {result['models']['U1_URLNet']['phishing_prob']:.2%}")
            print(f"  U2 (DeBERTa):  {result['models']['U2_DeBERTa']['prediction']:<12} "
                  f"Phishing: {result['models']['U2_DeBERTa']['phishing_prob']:.2%}")
            print(f"  U4 (XGBoost):  {result['models']['U4_XGBoost']['prediction']:<12} "
                  f"Phishing: {result['models']['U4_XGBoost']['phishing_prob']:.2%}")

            print("\nStage 2: Feature Engineering")
            print(f"  Feature Score:       {result['models']['Features']['score']:.2%}")
            print(f"  Typosquatting Score: {result['models']['Features']['typosquatting_score']:.2%}")
            print(f"  Domain Age:          {result['models']['Features']['domain_age_days']} days")
            print(f"  New Domain Flag:     {result['models']['Features']['is_new_domain']}")

            print(f"\n{'─' * 80}")
            print("Stage 3: Meta-Ensemble")
            print(f"  Phishing Score: {result['phishing_score']:.2%}")
            print(f"  Votes:          {result['votes']}")
            print(f"  Confidence:     {result['confidence']:.2%}")
            print(f"  Latency:        {result['latency_ms']}ms")

            verdict = "[!] PHISHING DETECTED" if result['is_phishing'] else "[OK] SAFE"
            print(f"\nFinal Verdict: {verdict}")
            print(f"{'=' * 80}\n")

        return result

    def __del__(self):
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)


if __name__ == "__main__":
    shield = PhishingShield2()
    test_urls = [
        "https://www.google.com",
        "http://paypa1-secure-login.xyz/verify",
        "https://www.paypal.com",
        "http://amazon-security-alert.com/signin",
        "http://192.168.1.1/secure/login.php",
    ]
    for url in test_urls:
        shield.analyze(url)
