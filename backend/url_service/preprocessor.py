import idna
try:
    from confusable_homoglyphs import confusables
except Exception:  # pragma: no cover
    confusables = None
try:
    import tldextract
except Exception:  # pragma: no cover
    tldextract = None
import re
from typing import Tuple, List
import aiohttp

class URLPreprocessor:
    def __init__(self):
        self.brand_domains = {
            'paypal': 'paypal.com',
            'amazon': 'amazon.com',
            'apple': 'apple.com',
            'microsoft': 'microsoft.com',
            'google': 'google.com'
        }
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL: decode punycode, lowercase, strip whitespace"""
        url = url.strip().lower()
        
        # Decode punycode domains
        if 'xn--' in url:
            try:
                parts = url.split('//')
                if len(parts) > 1:
                    domain_part = parts[1].split('/')[0]
                    decoded = idna.decode(domain_part)
                    url = url.replace(domain_part, decoded)
            except:
                pass
        
        return url
    
    def detect_homoglyphs(self, url: str) -> Tuple[bool, str, float]:
        """Detect homoglyph attacks in domain"""
        extracted = self._extract(url)
        domain = extracted.domain
        
        for brand, legit_domain in self.brand_domains.items():
            if confusables is not None and confusables.is_confusable(domain, brand, greedy=True):
                return True, brand, 0.95
        
        # Check for digit substitutions (paypa1 -> paypal)
        for brand in self.brand_domains.keys():
            if self._is_digit_substitution(domain, brand):
                return True, brand, 0.90
        
        return False, "", 0.0
    
    def _is_digit_substitution(self, domain: str, brand: str) -> bool:
        """Check for common digit substitutions like 1->l, 0->o"""
        substitutions = {'1': 'l', '0': 'o', '3': 'e', '5': 's'}
        for digit, letter in substitutions.items():
            if digit in domain:
                test = domain.replace(digit, letter)
                if test == brand:
                    return True
        return False
    
    async def unwind_redirects(self, url: str, max_hops: int = 10) -> Tuple[str, int, List[str]]:
        """Follow redirect chain to final destination"""
        chain = [url]
        current_url = url
        
        async with aiohttp.ClientSession() as session:
            for _ in range(max_hops):
                try:
                    async with session.get(current_url, allow_redirects=False, timeout=5) as resp:
                        if resp.status in [301, 302, 303, 307, 308]:
                            next_url = resp.headers.get('Location')
                            if next_url:
                                chain.append(next_url)
                                current_url = next_url
                            else:
                                break
                        else:
                            break
                except:
                    break
        
        return current_url, len(chain) - 1, chain
    
    def has_ip_address(self, url: str) -> bool:
        """Check if URL contains IP address instead of domain"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))

    def _extract(self, url: str):
        if tldextract is not None:
            return tldextract.extract(url)
        host = url.split('//')[-1].split('/')[0].split('@')[-1].split(':')[0]
        parts = [p for p in host.split('.') if p]
        suffix = parts[-1] if len(parts) >= 1 else ""
        domain = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ""
        return type("Extract", (), {"domain": domain, "suffix": suffix, "subdomain": subdomain})()
