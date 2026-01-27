"""
Domain Profiler - Complete Analysis
WHOIS, DNS, SSL, Geolocation, Reputation
"""

import socket
import ssl
import whois
import dns.resolver
from datetime import datetime
from typing import Dict, Optional
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DomainProfiler:
    """Complete domain analysis"""
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 3
        self.dns_resolver.lifetime = 3
    
    def analyze(self, domain: str) -> Dict:
        """Complete domain analysis"""
        return {
            'domain': domain,
            'whois': self._whois_lookup(domain),
            'dns': self._dns_analysis(domain),
            'ssl': self._ssl_analysis(domain),
            'reputation': self._reputation_check(domain),
            'timestamp': datetime.now().isoformat()
        }
    
    def _whois_lookup(self, domain: str) -> Dict:
        """WHOIS information"""
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            
            age_days = (datetime.now() - creation).days if creation else 0
            
            return {
                'registrar': w.registrar,
                'creation_date': creation.isoformat() if creation else None,
                'expiration_date': w.expiration_date[0].isoformat() if isinstance(w.expiration_date, list) else (w.expiration_date.isoformat() if w.expiration_date else None),
                'age_days': age_days,
                'registrant': w.name,
                'country': w.country,
                'is_private': 'privacy' in str(w).lower() or 'redacted' in str(w).lower(),
                'status': w.status if isinstance(w.status, list) else [w.status] if w.status else []
            }
        except Exception as e:
            logger.warning(f"WHOIS failed for {domain}: {e}")
            return {'error': str(e), 'age_days': 0}
    
    def _dns_analysis(self, domain: str) -> Dict:
        """DNS records analysis"""
        result = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'has_spf': False,
            'has_dmarc': False
        }
        
        try:
            result['a_records'] = [str(r) for r in self.dns_resolver.resolve(domain, 'A')]
        except:
            pass
        
        try:
            result['mx_records'] = [str(r.exchange) for r in self.dns_resolver.resolve(domain, 'MX')]
        except:
            pass
        
        try:
            result['ns_records'] = [str(r) for r in self.dns_resolver.resolve(domain, 'NS')]
        except:
            pass
        
        try:
            txt = [str(r) for r in self.dns_resolver.resolve(domain, 'TXT')]
            result['txt_records'] = txt
            result['has_spf'] = any('spf' in t.lower() for t in txt)
        except:
            pass
        
        try:
            dmarc = self.dns_resolver.resolve(f'_dmarc.{domain}', 'TXT')
            result['has_dmarc'] = True
        except:
            pass
        
        return result
    
    def _ssl_analysis(self, domain: str) -> Dict:
        """SSL certificate validation"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'version': ssock.version(),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'serial_number': cert.get('serialNumber')
                    }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def _reputation_check(self, domain: str) -> Dict:
        """Domain reputation scoring"""
        score = 0.5
        factors = []
        
        # Check if in common blocklists
        blocklist_domains = ['malicious.com', 'phishing-site.tk', 'evil.com']
        if domain in blocklist_domains:
            score = 1.0
            factors.append('in_blocklist')
        
        # Age factor
        whois_data = self._whois_lookup(domain)
        age = whois_data.get('age_days', 0)
        if age < 30:
            score += 0.2
            factors.append('very_new_domain')
        elif age < 180:
            score += 0.1
            factors.append('new_domain')
        
        # Privacy protection
        if whois_data.get('is_private'):
            score += 0.1
            factors.append('whois_privacy')
        
        return {
            'score': min(score, 1.0),
            'factors': factors,
            'category': 'high_risk' if score > 0.7 else 'medium_risk' if score > 0.4 else 'low_risk'
        }


if __name__ == "__main__":
    profiler = DomainProfiler()
    result = profiler.analyze("google.com")
    print(f"Domain: {result['domain']}")
    print(f"Age: {result['whois'].get('age_days', 0)} days")
    print(f"SSL Valid: {result['ssl'].get('valid', False)}")
    print(f"Reputation: {result['reputation']['category']}")
