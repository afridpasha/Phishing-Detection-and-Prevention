import math
import re
from datetime import datetime, timezone
from typing import Dict
from urllib.parse import parse_qs, urlparse

try:
    import tldextract
except Exception:  # pragma: no cover
    tldextract = None
try:
    import whois
except Exception:  # pragma: no cover
    whois = None


class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'}
        self.url_shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'}

    def extract_features(self, url: str) -> Dict[str, float]:
        parsed = urlparse(url)
        extracted = self._extract(url)
        host = parsed.netloc.split('@')[-1].split(':')[0].lower()
        features: Dict[str, float] = {}

        # Length features (10)
        features['url_length'] = float(len(url))
        features['domain_length'] = float(len(extracted.domain))
        features['path_length'] = float(len(parsed.path))
        features['query_length'] = float(len(parsed.query))
        features['fragment_length'] = float(len(parsed.fragment))
        features['num_subdomains'] = float(len(extracted.subdomain.split('.')) if extracted.subdomain else 0)
        features['num_path_segments'] = float(len([p for p in parsed.path.split('/') if p]))
        features['num_query_params'] = float(len(parse_qs(parsed.query)))
        features['num_dots'] = float(url.count('.'))
        features['num_hyphens'] = float(url.count('-'))

        # Character ratio features (8)
        features['special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url) if url else 0.0
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0.0
        features['uppercase_ratio'] = sum(c.isupper() for c in url) / len(url) if url else 0.0
        features['vowel_ratio'] = sum(c in 'aeiouAEIOU' for c in url) / len(url) if url else 0.0
        features['slash_ratio'] = url.count('/') / len(url) if url else 0.0
        features['at_sign_count'] = float(url.count('@'))
        features['equals_sign_count'] = float(url.count('='))
        features['ampersand_count'] = float(url.count('&'))

        # Encoding features (6)
        features['has_ip_address'] = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host) else 0.0
        features['ip_in_url'] = features['has_ip_address']
        features['has_port_number'] = 1.0 if parsed.port else 0.0
        features['has_url_encoding'] = 1.0 if '%' in url else 0.0
        features['url_encoding_ratio'] = url.count('%') / len(url) if url else 0.0
        features['has_base64'] = 1.0 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', url) else 0.0

        # Domain features (15)
        features['domain_entropy'] = self._calculate_entropy(extracted.domain)
        features['tld_risk_score'] = 0.8 if extracted.suffix in self.suspicious_tlds else 0.2
        features['is_suspicious_tld'] = 1.0 if extracted.suffix in self.suspicious_tlds else 0.0
        features['subdomain_depth'] = features['num_subdomains']
        features['has_www'] = 1.0 if 'www' in extracted.subdomain else 0.0
        features['is_known_shortener'] = 1.0 if host in self.url_shorteners else 0.0

        whois_info = self._safe_whois(host)
        features['domain_age_days'] = float(self._domain_age_days(whois_info))
        features['domain_expiry_days'] = float(self._domain_expiry_days(whois_info))
        features['registrar_risk_score'] = 0.5
        features['has_privacy_protection'] = 0.0
        features['ssl_age_days'] = 0.0
        features['ssl_is_free_ca'] = 0.0
        features['ssl_wildcard'] = 0.0
        features['ssl_san_count'] = 0.0
        features['ct_log_age_hours'] = 0.0

        # Homoglyph features (5)
        features['has_homoglyph'] = 0.0
        features['homoglyph_brand'] = 0.0
        features['homoglyph_confidence'] = 0.0
        features['has_punycode'] = 1.0 if 'xn--' in url else 0.0
        features['has_mixed_scripts'] = 0.0

        # Redirect features (8)
        features['redirect_count'] = 0.0
        features['has_meta_refresh'] = 0.0
        features['redirect_chain_length'] = 0.0
        features['final_dest_different'] = 0.0
        features['crosses_tld_boundary'] = 0.0
        features['uses_url_shortener'] = features['is_known_shortener']
        features['shortener_hops'] = 0.0
        features['js_redirect_detected'] = 0.0

        # Path features (10)
        lower_url = url.lower()
        features['path_entropy'] = self._calculate_entropy(parsed.path)
        features['has_login_keyword'] = 1.0 if any(k in lower_url for k in ['login', 'signin', 'account']) else 0.0
        features['has_account_keyword'] = 1.0 if 'account' in lower_url else 0.0
        features['has_secure_keyword'] = 1.0 if 'secure' in lower_url else 0.0
        features['has_verify_keyword'] = 1.0 if 'verify' in lower_url else 0.0
        features['has_update_keyword'] = 1.0 if 'update' in lower_url else 0.0
        features['path_double_slash'] = 1.0 if '//' in parsed.path else 0.0
        features['path_relative'] = 1.0 if parsed.path.startswith('./') or parsed.path.startswith('../') else 0.0
        features['has_file_extension'] = 1.0 if '.' in parsed.path.split('/')[-1] else 0.0
        features['file_extension_risk'] = 0.5

        # Threat intel features (5)
        features['in_virustotal'] = 0.0
        features['vt_detection_ratio'] = 0.0
        features['in_phishtank'] = 0.0
        features['in_urlhaus'] = 0.0
        features['in_otx'] = 0.0

        # Brand similarity features (10)
        features['top_brand_similarity'] = 0.0
        features['brand_name_in_url'] = 0.0
        features['brand_name_in_path'] = 0.0
        features['brand_name_in_subdomain'] = 0.0
        features['brand_in_domain_vs_path_mismatch'] = 0.0
        features['levenshtein_distance_top_brand'] = 10.0
        features['soundex_match_brand'] = 0.0
        features['keyword_brand_combo'] = 0.0
        features['num_brands_mentioned'] = 0.0
        features['brand_in_query_only'] = 0.0

        return features

    def _safe_whois(self, domain: str) -> Dict:
        if whois is None:
            return {}
        try:
            data = whois.whois(domain)
            return dict(data) if data else {}
        except Exception:
            return {}

    def _domain_age_days(self, whois_data: Dict) -> int:
        created = whois_data.get('creation_date')
        if isinstance(created, list) and created:
            created = created[0]
        if not isinstance(created, datetime):
            return 0
        now = datetime.now(timezone.utc)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, int((now - created).total_seconds() // 86400))

    def _domain_expiry_days(self, whois_data: Dict) -> int:
        expiry = whois_data.get('expiration_date')
        if isinstance(expiry, list) and expiry:
            expiry = expiry[0]
        if not isinstance(expiry, datetime):
            return 0
        now = datetime.now(timezone.utc)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return max(0, int((expiry - now).total_seconds() // 86400))

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _extract(self, url: str):
        if tldextract is not None:
            return tldextract.extract(url)
        host = urlparse(url).netloc.split("@")[-1].split(":")[0]
        parts = [p for p in host.split(".") if p]
        suffix = parts[-1] if len(parts) >= 1 else ""
        domain = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
        return type("Extract", (), {"domain": domain, "suffix": suffix, "subdomain": subdomain})()
