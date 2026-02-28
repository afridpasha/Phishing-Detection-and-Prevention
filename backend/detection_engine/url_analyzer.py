"""
URL Analysis Module - Pattern Matching & Encoding Detection
Real-Time Phishing Detection System

This module analyzes URLs for phishing indicators including encoding,
redirects, homoglyphs, and suspicious patterns.
"""

import re
import base64
import urllib.parse
from typing import Dict, List, Tuple, Optional
import requests
from datetime import datetime
import logging
import joblib
import numpy as np
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLAnalyzer:
    """
    Comprehensive URL analysis for phishing detection
    
    Features:
    - Pattern matching and suspicious keyword detection
    - URL encoding detection (Base64, hex, Unicode)
    - HTTP redirect chain following
    - Homoglyph detection
    - URL shortener resolution
    - Parameter and fragment analysis
    """
    
    def __init__(self, timeout: int = 5, max_redirects: int = 10):
        self.timeout = timeout
        self.max_redirects = max_redirects
        
        # Load trained ML model
        self.ml_model = None
        self.feature_cols = None
        self._load_ml_model()
        
        # Suspicious keywords in URLs
        self.suspicious_keywords = [
            'verify', 'account', 'update', 'secure', 'login', 'signin',
            'banking', 'confirm', 'suspend', 'restore', 'validate',
            'credential', 'password', 'urgent', 'limited', 'expire'
        ]
        
        # Known URL shorteners
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'mcaf.ee'
        ]
        
        # Common TLDs used in phishing
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
            '.date', '.racing', '.review', '.stream', '.download'
        ]
        
        # Brand names for impersonation detection
        self.brand_names = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'facebook', 'netflix', 'bankofamerica', 'chase', 'wellsfargo'
        ]
    
    def _load_ml_model(self):
        """Load trained ML model"""
        try:
            model_path = 'models/url_phishing_ensemble.joblib'
            features_path = 'models/url_feature_columns.joblib'
            scaler_path = 'models/url_feature_scaler.joblib'
            
            if os.path.exists(model_path) and os.path.exists(features_path):
                self.ml_model = joblib.load(model_path)
                self.feature_cols = joblib.load(features_path)
                self.scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
                logger.info("ML model loaded successfully")
            else:
                logger.warning("ML model not found, using pattern-based detection only")
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
    
    def _extract_ml_features(self, url: str, parsed) -> np.ndarray:
        """Extract features for ML model (matching training features)"""
        import tldextract
        
        extracted = tldextract.extract(url)
        
        features = {
            'url_length': len(url),
            'domain_length': len(parsed.netloc),
            'path_length': len(parsed.path),
            'has_https': 1.0 if parsed.scheme == 'https' else 0.0,
            'has_http': 1.0 if parsed.scheme == 'http' else 0.0,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_slashes': url.count('/'),
            'num_question_marks': url.count('?'),
            'num_equal_signs': url.count('='),
            'num_at_symbols': url.count('@'),
            'num_ampersands': url.count('&'),
            'num_digits': sum(c.isdigit() for c in url),
            'num_percent': url.count('%'),
            'num_subdomains': parsed.netloc.count('.') - 1 if '.' in parsed.netloc else 0,
            'has_ip_address': 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc) else 0.0,
            'has_port': 1.0 if ':' in parsed.netloc and not parsed.netloc.startswith('[') else 0.0,
            'has_suspicious_words': 1.0 if any(kw in url.lower() for kw in self.suspicious_keywords) else 0.0,
            'has_shortener': 1.0 if any(sh in parsed.netloc for sh in self.url_shorteners) else 0.0,
            'digit_ratio': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0.0,
            'domain_entropy': self._calculate_entropy(parsed.netloc),
            'domain_has_digits': 1.0 if any(c.isdigit() for c in parsed.netloc) else 0.0,
            'domain_has_hyphens': 1.0 if '-' in parsed.netloc else 0.0,
            'fragment_length': float(len(parsed.fragment)),
            'has_login_path': 1.0 if 'login' in parsed.path.lower() else 0.0,
            'has_redirect_param': 1.0 if any(p in parsed.query.lower() for p in ['redirect', 'url', 'next']) else 0.0,
            'https_in_domain': 1.0 if 'https' in parsed.netloc.lower() else 0.0,
            'is_brand_similar': 1.0 if any(b in parsed.netloc.lower() for b in self.brand_names) else 0.0,
            'is_http': 1.0 if parsed.scheme == 'http' else 0.0,
            'is_https': 1.0 if parsed.scheme == 'https' else 0.0,
            'is_ip_address': 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc) else 0.0,
            'is_shortener': 1.0 if any(sh in parsed.netloc for sh in self.url_shorteners) else 0.0,
            'letter_ratio': sum(c.isalpha() for c in url) / len(url) if len(url) > 0 else 0.0,
            'max_consecutive_digits': self._max_consecutive_chars(url, str.isdigit),
            'max_consecutive_dots': float(self._max_consecutive_chars(url, lambda c: c == '.')),
            'max_consecutive_hyphens': float(self._max_consecutive_chars(url, lambda c: c == '-')),
            'min_brand_distance': self._min_brand_distance(parsed.netloc),
            'num_exclamation': float(url.count('!')),
            'num_hashtags': float(url.count('#')),
            'num_letters': float(sum(c.isalpha() for c in url)),
            'num_query_params': float(len(urllib.parse.parse_qs(parsed.query))),
            'num_suspicious_words': float(sum(1 for kw in self.suspicious_keywords if kw in url.lower())),
            'path_depth': float(parsed.path.count('/')),
            'query_length': float(len(parsed.query)),
            'tld_length': float(len(extracted.suffix)),
            'tld_suspicious': 1.0 if any(parsed.netloc.endswith(tld) for tld in self.suspicious_tlds) else 0.0,
            'url_entropy': self._calculate_entropy(url),
            'special_char_ratio': sum(not c.isalnum() for c in url) / len(url) if len(url) > 0 else 0.0
        }
        
        # Return features in correct order
        return np.array([features[col] for col in self.feature_cols]).reshape(1, -1)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        from collections import Counter
        counts = Counter(text)
        probs = [count / len(text) for count in counts.values()]
        return -sum(p * np.log2(p) for p in probs if p > 0)
    
    def _max_consecutive_chars(self, text: str, condition) -> float:
        """Find max consecutive characters matching condition"""
        max_count = 0
        current_count = 0
        for char in text:
            if condition(char):
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return float(max_count)
    
    def _min_brand_distance(self, domain: str) -> float:
        """Calculate minimum edit distance to known brands"""
        if not self.brand_names:
            return 10.0
        domain_lower = domain.lower()
        min_dist = 10.0
        for brand in self.brand_names:
            if brand in domain_lower:
                return 0.0
        return min_dist
        
    def analyze_url(self, url: str, follow_redirects: bool = True) -> Dict[str, any]:
        """
        Comprehensive URL analysis
        
        Args:
            url: URL to analyze
            follow_redirects: Whether to follow redirect chains
            
        Returns:
            Analysis results dictionary
        """
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'suspicious_score': 0.0,
            'indicators': []
        }
        
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
            results['parsed'] = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
        except Exception as e:
            logger.error(f"URL parsing error: {e}")
            results['error'] = str(e)
            return results
        
        # Pattern analysis
        pattern_results = self._analyze_patterns(url, parsed)
        results.update(pattern_results)
        
        # Encoding detection
        encoding_results = self._detect_encoding(url, parsed)
        results.update(encoding_results)
        
        # Domain analysis
        domain_results = self._analyze_domain(parsed.netloc)
        results.update(domain_results)
        
        # URL structure analysis
        structure_results = self._analyze_structure(url, parsed)
        results.update(structure_results)
        
        # Redirect analysis
        if follow_redirects:
            redirect_results = self._follow_redirects(url)
            results['redirects'] = redirect_results
        
        # Use ML model if available
        if self.ml_model is not None and self.feature_cols is not None:
            try:
                features = self._extract_ml_features(url, parsed)
                # Apply scaler if available
                if self.scaler is not None:
                    features = self.scaler.transform(features)
                ml_proba = self.ml_model.predict_proba(features)[0][1]  # Probability of phishing
                results['ml_score'] = float(ml_proba)
                results['ml_prediction'] = 'phishing' if ml_proba > 0.5 else 'legitimate'
                # Use ML score as primary
                results['suspicious_score'] = ml_proba
            except Exception as e:
                logger.error(f"ML prediction error: {e}")
                # Fallback to pattern-based
                results['suspicious_score'] = self._calculate_suspicious_score(results)
        else:
            # Calculate overall suspicious score (pattern-based)
            results['suspicious_score'] = self._calculate_suspicious_score(results)
        
        results['is_suspicious'] = results['suspicious_score'] > 0.5
        results['risk_level'] = self._categorize_risk(results['suspicious_score'])
        
        return results
    
    def _analyze_patterns(self, url: str, parsed) -> Dict[str, any]:
        """Analyze URL for suspicious patterns"""
        indicators = []
        score = 0.0
        
        # Check for IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, parsed.netloc):
            indicators.append('ip_address_used')
            score += 0.3
        
        # Check for suspicious keywords
        url_lower = url.lower()
        found_keywords = [kw for kw in self.suspicious_keywords if kw in url_lower]
        if found_keywords:
            indicators.append(f'suspicious_keywords: {", ".join(found_keywords[:3])}')
            score += 0.1 * len(found_keywords)
        
        # Check for @ symbol (URL obfuscation)
        if '@' in parsed.netloc:
            indicators.append('at_symbol_in_domain')
            score += 0.4
        
        # Check for excessive subdomains
        subdomain_count = parsed.netloc.count('.')
        if subdomain_count > 3:
            indicators.append(f'excessive_subdomains: {subdomain_count}')
            score += 0.2
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if parsed.netloc.endswith(tld):
                indicators.append(f'suspicious_tld: {tld}')
                score += 0.25
                break
        
        # Check for brand name impersonation in subdomain
        for brand in self.brand_names:
            if brand in parsed.netloc.lower() and not parsed.netloc.lower().endswith(f'{brand}.com'):
                indicators.append(f'brand_impersonation: {brand}')
                score += 0.35
                break
        
        return {
            'pattern_indicators': indicators,
            'pattern_score': min(score, 1.0)
        }
    
    def _detect_encoding(self, url: str, parsed) -> Dict[str, any]:
        """Detect URL encoding techniques"""
        indicators = []
        score = 0.0
        
        # Base64 encoding detection
        if self._contains_base64(url):
            indicators.append('base64_encoding_detected')
            score += 0.3
        
        # Hex encoding detection
        hex_pattern = r'%[0-9A-Fa-f]{2}'
        hex_count = len(re.findall(hex_pattern, url))
        if hex_count > 5:
            indicators.append(f'excessive_hex_encoding: {hex_count}')
            score += 0.2
        
        # Unicode/Punycode detection
        if 'xn--' in parsed.netloc:
            indicators.append('punycode_detected')
            score += 0.25
        
        # Double encoding
        if '%25' in url:
            indicators.append('double_encoding_detected')
            score += 0.3
        
        return {
            'encoding_indicators': indicators,
            'encoding_score': min(score, 1.0)
        }
    
    def _analyze_domain(self, domain: str) -> Dict[str, any]:
        """Analyze domain characteristics"""
        import tldextract
        
        indicators = []
        score = 0.0
        
        # Extract domain components
        extracted = tldextract.extract(domain)
        
        # Check domain length
        domain_length = len(extracted.domain)
        if domain_length > 20:
            indicators.append(f'long_domain: {domain_length} chars')
            score += 0.15
        
        # Check for hyphens (common in phishing)
        hyphen_count = extracted.domain.count('-')
        if hyphen_count > 2:
            indicators.append(f'multiple_hyphens: {hyphen_count}')
            score += 0.2
        
        # Check for numbers in domain
        if any(c.isdigit() for c in extracted.domain):
            indicators.append('numbers_in_domain')
            score += 0.1
        
        # Check for homoglyphs
        if self._contains_homoglyphs(extracted.domain):
            indicators.append('homoglyph_detected')
            score += 0.4
        
        # Check if domain is a URL shortener
        if domain in self.url_shorteners:
            indicators.append('url_shortener')
            score += 0.15
        
        return {
            'domain_indicators': indicators,
            'domain_score': min(score, 1.0),
            'domain_parts': {
                'subdomain': extracted.subdomain,
                'domain': extracted.domain,
                'suffix': extracted.suffix
            }
        }
    
    def _analyze_structure(self, url: str, parsed) -> Dict[str, any]:
        """Analyze URL structure"""
        indicators = []
        score = 0.0
        
        # URL length
        url_length = len(url)
        if url_length > 100:
            indicators.append(f'long_url: {url_length} chars')
            score += 0.15
        
        # Path depth
        path_depth = parsed.path.count('/')
        if path_depth > 5:
            indicators.append(f'deep_path: {path_depth} levels')
            score += 0.1
        
        # Query parameters
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            param_count = len(params)
            if param_count > 5:
                indicators.append(f'many_parameters: {param_count}')
                score += 0.1
            
            # Check for suspicious parameter names
            suspicious_params = ['redirect', 'url', 'continue', 'return', 'goto']
            found_params = [p for p in params if any(sp in p.lower() for sp in suspicious_params)]
            if found_params:
                indicators.append(f'suspicious_params: {", ".join(found_params[:2])}')
                score += 0.2
        
        # Fragment
        if parsed.fragment:
            indicators.append('has_fragment')
            score += 0.05
        
        return {
            'structure_indicators': indicators,
            'structure_score': min(score, 1.0)
        }
    
    def _follow_redirects(self, url: str) -> Dict[str, any]:
        """Follow redirect chain"""
        redirect_chain = []
        current_url = url
        
        try:
            session = requests.Session()
            session.max_redirects = self.max_redirects
            
            for i in range(self.max_redirects):
                try:
                    response = session.head(
                        current_url,
                        allow_redirects=False,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    redirect_chain.append({
                        'url': current_url,
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    })
                    
                    # Check if redirected
                    if response.status_code in [301, 302, 303, 307, 308]:
                        if 'Location' in response.headers:
                            current_url = response.headers['Location']
                            # Handle relative redirects
                            if not current_url.startswith('http'):
                                parsed = urllib.parse.urlparse(url)
                                current_url = f"{parsed.scheme}://{parsed.netloc}{current_url}"
                        else:
                            break
                    else:
                        break
                        
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Redirect follow error: {e}")
                    break
            
            return {
                'chain': redirect_chain,
                'redirect_count': len(redirect_chain) - 1,
                'final_url': current_url,
                'has_redirects': len(redirect_chain) > 1
            }
            
        except Exception as e:
            logger.error(f"Redirect analysis error: {e}")
            return {
                'chain': [],
                'redirect_count': 0,
                'final_url': url,
                'error': str(e)
            }
    
    def _contains_base64(self, text: str) -> bool:
        """Check if text contains Base64 encoding"""
        # Look for Base64 patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        for match in matches:
            try:
                decoded = base64.b64decode(match)
                # Check if decoded text is printable
                if all(32 <= b < 127 for b in decoded):
                    return True
            except:
                pass
        
        return False
    
    def _contains_homoglyphs(self, text: str) -> bool:
        """Detect homoglyph characters"""
        # Common homoglyph pairs
        homoglyphs = {
            'a': ['а', 'ɑ'], 'c': ['с', 'ϲ'], 'e': ['е', 'ҽ'],
            'o': ['о', '0', 'օ'], 'p': ['р'], 's': ['ѕ'],
            'x': ['х'], 'y': ['у'], 'i': ['і', '1', 'l']
        }
        
        for char in text.lower():
            for latin, similar in homoglyphs.items():
                if char in similar:
                    return True
        
        return False
    
    def _calculate_suspicious_score(self, results: Dict) -> float:
        """Calculate overall suspicious score"""
        # Weighted average of individual scores
        weights = {
            'pattern_score': 0.35,
            'encoding_score': 0.25,
            'domain_score': 0.25,
            'structure_score': 0.15
        }
        
        score = 0.0
        for key, weight in weights.items():
            if key in results:
                score += results[key] * weight
        
        return min(score, 1.0)
    
    def _categorize_risk(self, score: float) -> str:
        """Categorize risk level"""
        if score < 0.3:
            return 'low'
        elif score < 0.7:
            return 'medium'
        else:
            return 'high'
    
    def batch_analyze(self, urls: List[str]) -> List[Dict[str, any]]:
        """Analyze multiple URLs"""
        results = []
        for url in urls:
            try:
                result = self.analyze_url(url, follow_redirects=False)
                results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing {url}: {e}")
                results.append({
                    'url': url,
                    'error': str(e),
                    'suspicious_score': 0.5
                })
        return results


class URLDefanger:
    """Defang and refang URLs for safe handling"""
    
    @staticmethod
    def defang(url: str) -> str:
        """Defang URL to make it non-clickable"""
        url = url.replace('http://', 'hxxp://')
        url = url.replace('https://', 'hxxps://')
        url = url.replace('.', '[.]')
        return url
    
    @staticmethod
    def refang(url: str) -> str:
        """Refang URL to restore original format"""
        url = url.replace('hxxp://', 'http://')
        url = url.replace('hxxps://', 'https://')
        url = url.replace('[.]', '.')
        return url


# Utility functions
def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from text"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def is_valid_url(url: str) -> bool:
    """Check if URL is valid"""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


if __name__ == "__main__":
    # Example usage
    print("Initializing URL Analyzer...")
    
    analyzer = URLAnalyzer()
    
    # Test URLs
    test_urls = [
        "http://paypal-verify.suspicious-site.tk/login?redirect=https://real-paypal.com",
        "https://www.google.com",
        "http://192.168.1.1/admin",
        "https://bit.ly/abc123"
    ]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"Analyzing: {url}")
        print('='*60)
        
        result = analyzer.analyze_url(url, follow_redirects=False)
        
        print(f"Suspicious Score: {result['suspicious_score']:.2%}")
        print(f"Risk Level: {result['risk_level'].upper()}")
        print(f"Is Suspicious: {'YES' if result['is_suspicious'] else 'NO'}")
        
        if result.get('pattern_indicators'):
            print(f"\nPattern Indicators: {', '.join(result['pattern_indicators'])}")
        if result.get('encoding_indicators'):
            print(f"Encoding Indicators: {', '.join(result['encoding_indicators'])}")
        if result.get('domain_indicators'):
            print(f"Domain Indicators: {', '.join(result['domain_indicators'])}")
