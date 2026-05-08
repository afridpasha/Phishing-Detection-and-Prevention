"""
EMAIL SHIELD — EMAIL PHISHING DETECTION
Category 3: Email Phishing Detection

Architecture:
  E1: phishbot/ScamLLM (RoBERTa phishing specialist)
  E2: mshenoda/roberta-spam (Enron + SpamAssassin)
  E3: microsoft/deberta-v3-base (AI-text detector)
  E4: microsoft/codebert-base (HTML analysis)
  Feature Engineering: Email-specific + header-spoofing features
  URL Analysis: extracts raw URLs AND <a href> anchor URLs from HTML

Performance:
  - Models run concurrently via ThreadPoolExecutor
  - Proper email parsing via Python stdlib email library
  - Spoofing header analysis (From vs Reply-To mismatch)
  - Anchor href extraction catches hidden phishing links
  - FP16 on GPU, tokenizer-level truncation

Target: >97.5% TPR | <0.8% FPR
"""

import re
import torch
import numpy as np
import email as email_lib          # Change #6: stdlib email parser
import email.policy
from email import message_from_string
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import warnings
import time
import logging

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)


class EmailShield:
    """
    Email Phishing Detection System — 4 AI models + feature engineering.
    """

    def __init__(self):
        print("=" * 80)
        print("EMAIL SHIELD — INITIALIZING")
        print("=" * 80)
        print("\nArchitecture: Email Phishing Detection")
        print("  Stage 1: E1 + E2 + E3 + E4 — concurrent ThreadPoolExecutor")
        print("  Stage 2: Feature Engineering (keywords + header-spoofing)")
        print("  Stage 3: URL Analysis (raw + anchor href extraction)")
        print("  Stage 4: Weighted Ensemble Decision\n")

        self._device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"  [Device] Using: {self._device.upper()}")
        self._executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="email_shield")
        self._load_models()
        self.url_shield = None

        print("\n[OK] Email Shield Ready!")
        print("=" * 80 + "\n")

    # ──────────────────────────────────────────────────────────────────────────
    # Model loading
    # ──────────────────────────────────────────────────────────────────────────
    def _load_models(self):
        print("  [1/4] E-1 (phishbot/ScamLLM)")
        self.e1_classifier = pipeline(
            "text-classification",
            model="models/email/E1_ScamLLM",
            device=0 if self._device == "cuda" else -1,
            truncation=True, max_length=512,   # Change #22
        )
        print("        [OK] Loaded")

        print("  [2/4] E-2 (mshenoda/roberta-spam)")
        self.e2_classifier = pipeline(
            "text-classification",
            model="models/email/E2_RoBERTa_Spam",
            device=0 if self._device == "cuda" else -1,
            truncation=True, max_length=512,   # Change #22
        )
        print("        [OK] Loaded")

        print("  [3/4] E-3 (DeBERTa AI-text detector)")
        self.e3_tokenizer = AutoTokenizer.from_pretrained("models/email/E3_DeBERTa_AIText")
        self.e3_model = AutoModelForSequenceClassification.from_pretrained("models/email/E3_DeBERTa_AIText")
        self.e3_model.eval()
        if self._device == "cuda":
            self.e3_model = self.e3_model.half().to("cuda")  # Change #20
        print("        [OK] Loaded")

        print("  [4/4] E-4 (CodeBERT HTML analysis)")
        self.e4_tokenizer = AutoTokenizer.from_pretrained("models/email/E4_CodeBERT_HTML")
        self.e4_model = AutoModelForSequenceClassification.from_pretrained("models/email/E4_CodeBERT_HTML")
        self.e4_model.eval()
        if self._device == "cuda":
            self.e4_model = self.e4_model.half().to("cuda")  # Change #20
        print("        [OK] Loaded")

    # ──────────────────────────────────────────────────────────────────────────
    # Change #6: Proper email parsing using Python stdlib email library
    # ──────────────────────────────────────────────────────────────────────────
    def parse_email(self, email_content: str) -> dict:
        """
        Parse email using Python's stdlib email library.
        Handles MIME multipart, base64 encoding, and multi-line headers correctly.
        """
        email_data = {
            'subject': '',
            'sender': '',
            'reply_to': '',
            'return_path': '',
            'body_text': '',
            'body_html': '',
            'headers': {},
        }

        try:
            msg = message_from_string(
                email_content,
                policy=email.policy.compat32
            )

            # Extract headers
            email_data['subject'] = msg.get('Subject', '') or ''
            email_data['sender'] = msg.get('From', '') or ''
            email_data['reply_to'] = msg.get('Reply-To', '') or ''        # Change #7
            email_data['return_path'] = msg.get('Return-Path', '') or ''  # Change #7
            email_data['headers'] = dict(msg.items())

            # Walk MIME parts to extract text and HTML bodies
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    cdisposition = str(part.get('Content-Disposition', ''))
                    if 'attachment' in cdisposition:
                        continue
                    if ctype == 'text/plain':
                        try:
                            text = part.get_payload(decode=True)
                            if text:
                                email_data['body_text'] += text.decode(
                                    part.get_content_charset() or 'utf-8', errors='replace'
                                )
                        except Exception:
                            pass
                    elif ctype == 'text/html':
                        try:
                            html = part.get_payload(decode=True)
                            if html:
                                email_data['body_html'] += html.decode(
                                    part.get_content_charset() or 'utf-8', errors='replace'
                                )
                        except Exception:
                            pass
            else:
                # Single-part message
                payload = msg.get_payload(decode=True)
                if payload:
                    decoded = payload.decode(
                        msg.get_content_charset() or 'utf-8', errors='replace'
                    )
                    if msg.get_content_type() == 'text/html':
                        email_data['body_html'] = decoded
                    else:
                        email_data['body_text'] = decoded

            # If no text body but have HTML, extract text from HTML
            if not email_data['body_text'] and email_data['body_html']:
                email_data['body_text'] = self._extract_text_from_html(email_data['body_html'])

        except Exception as e:
            # Fallback: naive line-split for plain-text format
            logger.warning(f"stdlib email parse failed ({e}), using fallback parser")
            email_data = self._parse_email_fallback(email_content)

        return email_data

    def _parse_email_fallback(self, content: str) -> dict:
        """Fallback parser for plain Subject:/From: formatted input (e.g. web UI)."""
        email_data = {
            'subject': '', 'sender': '', 'reply_to': '',
            'return_path': '', 'body_text': '', 'body_html': '', 'headers': {}
        }
        lines = content.split('\n')
        body_start = False
        body_lines = []
        for line in lines:
            if not body_start:
                if line.startswith('Subject:'):
                    email_data['subject'] = line.replace('Subject:', '').strip()
                elif line.startswith('From:'):
                    email_data['sender'] = line.replace('From:', '').strip()
                elif line.startswith('Reply-To:'):
                    email_data['reply_to'] = line.replace('Reply-To:', '').strip()
                elif line.strip() == '':
                    body_start = True
            else:
                body_lines.append(line)
        body = '\n'.join(body_lines)
        if '<html' in body.lower() or '<body' in body.lower():
            email_data['body_html'] = body
            email_data['body_text'] = self._extract_text_from_html(body)
        else:
            email_data['body_text'] = body
        return email_data

    def _extract_text_from_html(self, html: str) -> str:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            return soup.get_text(separator=' ', strip=True)
        except Exception:
            return html

    # ──────────────────────────────────────────────────────────────────────────
    # Change #7: Header spoofing detection
    # ──────────────────────────────────────────────────────────────────────────
    def _detect_header_spoofing(self, email_data: dict) -> dict:
        """
        Detect email header spoofing indicators:
        - From domain ≠ Reply-To domain
        - From domain ≠ Return-Path domain
        - Numeric characters in sender domain
        - Common no-reply patterns used in phishing
        """

        def _get_domain(addr: str) -> str:
            m = re.search(r'@([\w.\-]+)', addr)
            return m.group(1).lower() if m else ''

        from_domain = _get_domain(email_data.get('sender', ''))
        reply_to_domain = _get_domain(email_data.get('reply_to', ''))
        return_path_domain = _get_domain(email_data.get('return_path', ''))

        spoofing = {
            'from_domain': from_domain,
            'reply_to_domain': reply_to_domain,
            'return_path_domain': return_path_domain,
            'reply_to_mismatch': bool(reply_to_domain and reply_to_domain != from_domain),
            'return_path_mismatch': bool(return_path_domain and return_path_domain != from_domain),
            'sender_has_digits': bool(re.search(r'\d', from_domain)),
            'suspicious_sender': any(
                x in email_data.get('sender', '').lower()
                for x in ['noreply', 'no-reply', 'donotreply', 'service@', 'support@', 'info@']
            ),
            'spoofing_score': 0.0,
        }
        score = 0.0
        if spoofing['reply_to_mismatch']:
            score += 0.35
        if spoofing['return_path_mismatch']:
            score += 0.25
        if spoofing['sender_has_digits']:
            score += 0.10
        if spoofing['suspicious_sender']:
            score += 0.05
        spoofing['spoofing_score'] = min(score, 1.0)
        return spoofing

    # ──────────────────────────────────────────────────────────────────────────
    # Change #8: URL extraction — raw text + anchor hrefs from HTML
    # ──────────────────────────────────────────────────────────────────────────
    def extract_urls_from_email(self, email_data: dict) -> list:
        """
        Extract all URLs from email:
        1. Raw http:// matches in body text
        2. <a href="..."> anchor URLs from HTML body  ← Change #8
        """
        urls = set()

        # 1. Raw URL pattern from plain text
        raw_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls.update(re.findall(raw_pattern, email_data.get('body_text', ''), re.IGNORECASE))

        # 2. Anchor hrefs from HTML body (Change #8)
        if email_data.get('body_html'):
            try:
                soup = BeautifulSoup(email_data['body_html'], 'html.parser')
                for tag in soup.find_all('a', href=True):
                    href = tag['href'].strip()
                    if href.startswith(('http://', 'https://')):
                        urls.add(href)
                # Also check src attributes on img/script tags
                for tag in soup.find_all(['img', 'form'], src=True):
                    src = tag.get('src', '').strip()
                    if src.startswith(('http://', 'https://')):
                        urls.add(src)
                # Check form action URLs
                for tag in soup.find_all('form', action=True):
                    action = tag['action'].strip()
                    if action.startswith(('http://', 'https://')):
                        urls.add(action)
            except Exception as e:
                logger.warning(f"BeautifulSoup href extraction failed: {e}")

        return list(urls)

    # ──────────────────────────────────────────────────────────────────────────
    # Feature engineering
    # ──────────────────────────────────────────────────────────────────────────
    def extract_email_features(self, email_data: dict) -> dict:
        features = {}

        subject = email_data.get('subject', '').lower()
        sender = email_data.get('sender', '').lower()
        body = email_data.get('body_text', '').lower()
        full_text = f"{subject} {body}"

        features['subject_length'] = len(email_data.get('subject', ''))
        features['body_length'] = len(email_data.get('body_text', ''))
        features['has_html'] = 1 if email_data.get('body_html') else 0
        features['has_url'] = 1 if re.search(r'http[s]?://', body) else 0

        urgency = ['urgent', 'immediate', 'action required', 'expire', 'suspended',
                   'limited time', 'act now', 'verify your account', '24 hours']
        features['urgency_count'] = sum(1 for w in urgency if w in full_text)

        financial = ['$', 'payment', 'invoice', 'refund', 'credit card', 'bank',
                     'account', 'wire', 'transfer', 'fund', 'deposit']
        features['financial_count'] = sum(1 for w in financial if w in full_text)

        security = ['verify', 'confirm', 'validate', 'security', 'password',
                    'credentials', 'login', 'sign in', 'reset']
        features['security_count'] = sum(1 for w in security if w in full_text)

        brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix',
                  'bank', 'irs', 'fedex', 'dhl', 'chase', 'wellsfargo']
        features['brand_count'] = sum(1 for b in brands if b in full_text)

        features['has_click_here'] = 1 if 'click here' in full_text else 0
        features['has_dear_customer'] = 1 if 'dear customer' in full_text or 'dear user' in full_text else 0
        features['has_attachment'] = 1 if 'attachment' in full_text or 'attached' in full_text else 0
        features['exclamation_count'] = full_text.count('!')
        features['question_count'] = full_text.count('?')

        features['sender_suspicious'] = 1 if any(
            x in sender for x in ['noreply', 'no-reply', 'donotreply']) else 0
        features['sender_has_number'] = 1 if any(c.isdigit() for c in sender) else 0

        if email_data.get('body_html'):
            html = email_data['body_html']
            features['html_script_tags'] = html.lower().count('<script')
            features['html_iframe_tags'] = html.lower().count('<iframe')
            features['html_form_tags'] = html.lower().count('<form')
            features['html_hidden_elements'] = html.lower().count('hidden')
        else:
            features.update({
                'html_script_tags': 0, 'html_iframe_tags': 0,
                'html_form_tags': 0, 'html_hidden_elements': 0,
            })

        return features

    def _calculate_feature_score(self, features: dict, spoofing: dict) -> float:
        risk = 0
        risk += features.get('urgency_count', 0) * 3
        risk += features.get('financial_count', 0) * 2
        risk += features.get('security_count', 0) * 3
        risk += features.get('brand_count', 0) * 2
        risk += features.get('has_click_here', 0) * 4
        risk += features.get('has_dear_customer', 0) * 2
        risk += features.get('sender_suspicious', 0) * 3
        risk += features.get('html_script_tags', 0) * 2
        risk += features.get('html_iframe_tags', 0) * 3
        risk += features.get('html_form_tags', 0) * 2

        # Change #7: incorporate spoofing signal
        risk += spoofing.get('spoofing_score', 0) * 10  # High weight — very reliable signal

        return min(risk / 35.0, 1.0)

    # ──────────────────────────────────────────────────────────────────────────
    # Individual model predictions
    # ──────────────────────────────────────────────────────────────────────────
    def _predict_e1(self, text: str) -> dict:
        """E-1: ScamLLM (phishing specialist)."""
        result = self.e1_classifier(text[:512])[0]
        is_phishing = ('phish' in result['label'].lower() or
                       'scam' in result['label'].lower() or
                       'label_1' in result['label'].lower())
        score = result['score'] if is_phishing else (1 - result['score'])
        return {'is_phishing': is_phishing, 'score': float(score)}

    def _predict_e2(self, text: str) -> dict:
        """E-2: RoBERTa Spam (Enron trained)."""
        result = self.e2_classifier(text[:512])[0]
        is_spam = 'spam' in result['label'].lower() or 'label_1' in result['label'].lower()
        score = result['score'] if is_spam else (1 - result['score'])
        return {'is_phishing': is_spam, 'score': float(score)}

    def _predict_e3(self, text: str) -> dict:
        """E-3: DeBERTa AI-text detector."""
        # Change #22: tokenizer-level truncation
        inputs = self.e3_tokenizer(
            text, return_tensors="pt", truncation=True,
            max_length=512, padding=True
        )
        if self._device == "cuda":
            inputs = {k: v.to("cuda") for k, v in inputs.items()}
        with torch.no_grad():
            outputs = self.e3_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)[0].float().cpu().numpy()
        ai_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        return {'is_ai_generated': ai_prob > 0.5, 'score': ai_prob}

    def _predict_e4(self, html: str) -> dict:
        """E-4: CodeBERT HTML obfuscation analysis."""
        if not html:
            return {'is_obfuscated': False, 'score': 0.0}
        # Change #22: tokenizer-level truncation
        inputs = self.e4_tokenizer(
            html, return_tensors="pt", truncation=True,
            max_length=512, padding=True
        )
        if self._device == "cuda":
            inputs = {k: v.to("cuda") for k, v in inputs.items()}
        with torch.no_grad():
            outputs = self.e4_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)[0].float().cpu().numpy()
        obf_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        return {'is_obfuscated': obf_prob > 0.5, 'score': obf_prob}

    # ──────────────────────────────────────────────────────────────────────────
    # Main prediction
    # ──────────────────────────────────────────────────────────────────────────
    def predict(self, email_content: str) -> dict:
        """
        Predict if email is phishing.
        Change #6: Proper MIME-aware email parsing.
        Change #7: Header spoofing detection.
        Change #8: Anchor href URL extraction.
        Change #19: Parallel model execution.
        """
        if not email_content or not email_content.strip():
            return self._empty_result()

        if len(email_content) > 100_000:
            email_content = email_content[:100_000]

        t0 = time.perf_counter()

        # ── Parse email properly (Change #6) ─────────────────────────────────
        email_data = self.parse_email(email_content)
        full_text = f"{email_data['subject']} {email_data['body_text']}".strip() or "empty"

        # ── Header spoofing analysis (Change #7) ─────────────────────────────
        spoofing = self._detect_header_spoofing(email_data)

        # ── Stage 1: Run 4 models in parallel (Change #19) ───────────────────
        futures = {
            'e1': self._executor.submit(self._predict_e1, full_text),
            'e2': self._executor.submit(self._predict_e2, full_text),
            'e3': self._executor.submit(self._predict_e3, full_text),
            'e4': self._executor.submit(self._predict_e4, email_data.get('body_html', '')),
            'feat': self._executor.submit(self.extract_email_features, email_data),
        }

        e1_r = futures['e1'].result()
        e2_r = futures['e2'].result()
        e3_r = futures['e3'].result()
        e4_r = futures['e4'].result()
        features = futures['feat'].result()
        feature_score = self._calculate_feature_score(features, spoofing)

        # ── Stage 2: URL analysis — raw + href anchors (Change #8) ───────────
        urls_in_email = self.extract_urls_from_email(email_data)
        url_analysis = []
        url_phishing_detected = False

        if urls_in_email:
            try:
                if self.url_shield is None:
                    from backend.detectors.url_detector import PhishingShield2
                    self.url_shield = PhishingShield2()
                url_futures = {
                    url: self._executor.submit(self.url_shield.predict, url)
                    for url in urls_in_email[:8]  # Check up to 8 URLs
                }
                for url, fut in url_futures.items():
                    url_result = fut.result()
                    url_analysis.append({
                        'url': url,
                        'is_phishing': url_result['is_phishing'],
                        'score': url_result['phishing_score'],
                    })
                    if url_result['is_phishing']:
                        url_phishing_detected = True
            except Exception as e:
                logger.warning(f"URL analysis error: {e}")

        # ── Stage 3: Ensemble ─────────────────────────────────────────────────
        if url_phishing_detected:
            avg_url = sum(u['score'] for u in url_analysis) / len(url_analysis)
            weights = {'e1': 0.20, 'e2': 0.20, 'e3': 0.10, 'e4': 0.10, 'feat': 0.15, 'url': 0.25}
            ensemble_score = (
                weights['e1'] * e1_r['score'] +
                weights['e2'] * e2_r['score'] +
                weights['e3'] * e3_r['score'] +
                weights['e4'] * e4_r['score'] +
                weights['feat'] * feature_score +
                weights['url'] * avg_url
            )
            votes = sum([
                e1_r['is_phishing'], e2_r['is_phishing'],
                e3_r['is_ai_generated'], e4_r['is_obfuscated'],
                feature_score > 0.5, url_phishing_detected,
            ])
            total_votes = 6
        else:
            weights = {'e1': 0.30, 'e2': 0.25, 'e3': 0.15, 'e4': 0.10, 'feat': 0.20}
            ensemble_score = (
                weights['e1'] * e1_r['score'] +
                weights['e2'] * e2_r['score'] +
                weights['e3'] * e3_r['score'] +
                weights['e4'] * e4_r['score'] +
                weights['feat'] * feature_score
            )
            votes = sum([
                e1_r['is_phishing'], e2_r['is_phishing'],
                e3_r['is_ai_generated'], e4_r['is_obfuscated'],
                feature_score > 0.5,
            ])
            total_votes = 5

        # ── Stage 4: Final decision ───────────────────────────────────────────
        is_phishing = (ensemble_score > 0.55) and (votes >= 2)

        # Header spoofing override — high confidence signal
        if spoofing['reply_to_mismatch'] and ensemble_score > 0.35:
            is_phishing = True

        if url_phishing_detected:
            avg_url = sum(u['score'] for u in url_analysis) / len(url_analysis)
            if avg_url > 0.70:
                is_phishing = True
                ensemble_score = max(ensemble_score, avg_url)

        if ensemble_score > 0.85 or votes >= 4:
            is_phishing = True
        if ensemble_score < 0.15 and votes == 0 and not url_phishing_detected:
            is_phishing = False

        confidence = max(ensemble_score, 1 - ensemble_score)
        latency_ms = (time.perf_counter() - t0) * 1000

        return {
            'is_phishing': bool(is_phishing),
            'phishing_score': float(ensemble_score),
            'confidence': float(confidence),
            'votes': f"{votes}/{total_votes}",
            'latency_ms': round(latency_ms, 1),
            'email_data': {
                'subject': email_data.get('subject', ''),
                'sender': email_data.get('sender', ''),
                'reply_to': email_data.get('reply_to', ''),
                'has_html': bool(email_data.get('body_html')),
            },
            'spoofing': spoofing,          # Change #7
            'models': {
                'E1_ScamLLM': e1_r,
                'E2_RoBERTa_Spam': e2_r,
                'E3_AI_Text': e3_r,
                'E4_HTML_Analysis': e4_r,
                'Features': {
                    'score': float(feature_score),
                    'spoofing_score': float(spoofing['spoofing_score']),
                },
            },
            'url_analysis': url_analysis if url_analysis else None,
        }

    def _empty_result(self):
        return {
            'is_phishing': False, 'phishing_score': 0.0, 'confidence': 1.0,
            'votes': '0/5', 'latency_ms': 0.0,
            'email_data': {'subject': '', 'sender': '', 'reply_to': '', 'has_html': False},
            'spoofing': {'spoofing_score': 0.0, 'reply_to_mismatch': False, 'return_path_mismatch': False},
            'models': {
                'E1_ScamLLM': {'is_phishing': False, 'score': 0.0},
                'E2_RoBERTa_Spam': {'is_phishing': False, 'score': 0.0},
                'E3_AI_Text': {'is_ai_generated': False, 'score': 0.0},
                'E4_HTML_Analysis': {'is_obfuscated': False, 'score': 0.0},
                'Features': {'score': 0.0, 'spoofing_score': 0.0},
            },
            'url_analysis': None,
        }

    def __del__(self):
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)


if __name__ == "__main__":
    shield = EmailShield()
    test_email = """Subject: Urgent: Your PayPal Account Has Been Suspended
From: security@paypa1-verify.com
Reply-To: attacker@evil-domain.xyz

Dear Customer,
Your PayPal account has been suspended. Verify immediately:
<a href="http://paypa1-secure.xyz/verify">Click here</a>

PayPal Security Team
"""
    result = shield.predict(test_email)
    print(f"\nPhishing: {result['is_phishing']}")
    print(f"Score: {result['phishing_score']:.2%}")
    print(f"Spoofing detected: {result['spoofing']['reply_to_mismatch']}")
    print(f"Votes: {result['votes']}")
