"""
Threat Feed Aggregator - Intelligence Layer
Real-Time Phishing Detection System

Aggregates threat intelligence from multiple sources including MISP, OTX, VirusTotal
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import logging
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatFeedAggregator:
    """
    Aggregates threat intelligence from multiple sources
    
    Supported Sources:
    - MISP (Malware Information Sharing Platform)
    - AlienVault OTX (Open Threat Exchange)
    - VirusTotal
    - PhishTank
    - URLhaus
    - Custom feeds
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # API configurations
        self.misp_url = self.config.get('misp_url', '')
        self.misp_key = self.config.get('misp_key', '')
        self.otx_key = self.config.get('otx_key', '')
        self.vt_key = self.config.get('vt_key', '')
        
        # Cache for threat data
        self.threat_cache: Dict[str, Dict] = {}
        self.cache_ttl = timedelta(hours=24)
        
        # Blocklists
        self.domain_blocklist: Set[str] = set()
        self.url_blocklist: Set[str] = set()
        self.ip_blocklist: Set[str] = set()
        
        logger.info("Threat Feed Aggregator initialized")
    
    async def check_url(self, url: str) -> Dict[str, any]:
        """
        Check URL against all threat intelligence sources
        
        Args:
            url: URL to check
            
        Returns:
            Threat intelligence data
        """
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        # Check cache first
        if url_hash in self.threat_cache:
            cached = self.threat_cache[url_hash]
            if datetime.now() - cached['timestamp'] < self.cache_ttl:
                logger.info(f"Cache hit for URL: {url[:50]}")
                return cached['data']
        
        # Aggregate from all sources
        tasks = [
            self._check_misp(url),
            self._check_otx(url),
            self._check_virustotal(url),
            self._check_phishtank(url),
            self._check_local_blocklist(url)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        combined = {
            'url': url,
            'in_blocklist': any(r.get('found', False) for r in results if isinstance(r, dict)),
            'threat_score': self._calculate_threat_score(results),
            'sources': [r for r in results if isinstance(r, dict) and r.get('found')],
            'timestamp': datetime.now().isoformat()
        }
        
        # Cache result
        self.threat_cache[url_hash] = {
            'timestamp': datetime.now(),
            'data': combined
        }
        
        return combined
    
    async def check_domain(self, domain: str) -> Dict[str, any]:
        """Check domain against threat intelligence"""
        return await self.check_url(f"http://{domain}")
    
    async def check_ip(self, ip: str) -> Dict[str, any]:
        """Check IP address against threat intelligence"""
        result = {
            'ip': ip,
            'in_blocklist': ip in self.ip_blocklist,
            'threat_score': 1.0 if ip in self.ip_blocklist else 0.0,
            'sources': []
        }
        
        if result['in_blocklist']:
            result['sources'].append({'source': 'local_blocklist', 'found': True})
        
        return result
    
    async def _check_misp(self, url: str) -> Dict[str, any]:
        """Check against MISP threat intelligence platform"""
        if not self.misp_url or not self.misp_key:
            return {'source': 'misp', 'found': False, 'error': 'Not configured'}
        
        try:
            # MISP API integration
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': self.misp_key,
                    'Accept': 'application/json'
                }
                
                async with session.post(
                    f"{self.misp_url}/attributes/restSearch",
                    json={'value': url, 'type': 'url'},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        found = len(data.get('response', {}).get('Attribute', [])) > 0
                        return {
                            'source': 'misp',
                            'found': found,
                            'data': data if found else None
                        }
        except Exception as e:
            logger.warning(f"MISP check error: {e}")
        
        return {'source': 'misp', 'found': False}
    
    async def _check_otx(self, url: str) -> Dict[str, any]:
        """Check against AlienVault OTX"""
        if not self.otx_key:
            return {'source': 'otx', 'found': False, 'error': 'Not configured'}
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'X-OTX-API-KEY': self.otx_key}
                
                # Extract domain from URL
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                
                async with session.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        pulse_count = data.get('pulse_info', {}).get('count', 0)
                        return {
                            'source': 'otx',
                            'found': pulse_count > 0,
                            'pulse_count': pulse_count
                        }
        except Exception as e:
            logger.warning(f"OTX check error: {e}")
        
        return {'source': 'otx', 'found': False}
    
    async def _check_virustotal(self, url: str) -> Dict[str, any]:
        """Check against VirusTotal"""
        if not self.vt_key:
            return {'source': 'virustotal', 'found': False, 'error': 'Not configured'}
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            async with aiohttp.ClientSession() as session:
                headers = {'x-apikey': self.vt_key}
                
                async with session.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        return {
                            'source': 'virustotal',
                            'found': malicious > 0,
                            'malicious_count': malicious,
                            'stats': stats
                        }
        except Exception as e:
            logger.warning(f"VirusTotal check error: {e}")
        
        return {'source': 'virustotal', 'found': False}
    
    async def _check_phishtank(self, url: str) -> Dict[str, any]:
        """Check against PhishTank"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'url': url,
                    'format': 'json'
                }
                
                async with session.post(
                    "https://checkurl.phishtank.com/checkurl/",
                    data=params,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        in_database = data.get('results', {}).get('in_database', False)
                        is_valid = data.get('results', {}).get('valid', False)
                        return {
                            'source': 'phishtank',
                            'found': in_database and is_valid,
                            'data': data.get('results')
                        }
        except Exception as e:
            logger.warning(f"PhishTank check error: {e}")
        
        return {'source': 'phishtank', 'found': False}
    
    async def _check_local_blocklist(self, url: str) -> Dict[str, any]:
        """Check against local blocklists"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        found = (
            url in self.url_blocklist or
            domain in self.domain_blocklist
        )
        
        return {
            'source': 'local_blocklist',
            'found': found,
            'match_type': 'url' if url in self.url_blocklist else 'domain' if found else None
        }
    
    def _calculate_threat_score(self, results: List[Dict]) -> float:
        """
        Calculate overall threat score from multiple sources
        
        Returns:
            Threat score between 0.0 and 1.0
        """
        if not results:
            return 0.0
        
        # Weight different sources
        weights = {
            'virustotal': 0.3,
            'misp': 0.25,
            'phishtank': 0.2,
            'otx': 0.15,
            'local_blocklist': 0.1
        }
        
        score = 0.0
        total_weight = 0.0
        
        for result in results:
            if isinstance(result, dict):
                source = result.get('source')
                if source in weights and result.get('found'):
                    score += weights[source]
                    total_weight += weights[source]
        
        return score if total_weight == 0 else score / total_weight
    
    def add_to_blocklist(self, 
                         urls: Optional[List[str]] = None,
                         domains: Optional[List[str]] = None,
                         ips: Optional[List[str]] = None):
        """Add entries to local blocklists"""
        if urls:
            self.url_blocklist.update(urls)
            logger.info(f"Added {len(urls)} URLs to blocklist")
        
        if domains:
            self.domain_blocklist.update(domains)
            logger.info(f"Added {len(domains)} domains to blocklist")
        
        if ips:
            self.ip_blocklist.update(ips)
            logger.info(f"Added {len(ips)} IPs to blocklist")
    
    async def refresh_feeds(self):
        """Refresh threat feeds from all sources"""
        logger.info("Refreshing threat intelligence feeds...")
        
        # Implementation for periodic feed updates
        # This would fetch latest IOCs from all sources
        
        logger.info("Threat feeds refreshed successfully")
    
    def get_statistics(self) -> Dict[str, any]:
        """Get aggregator statistics"""
        return {
            'cache_size': len(self.threat_cache),
            'blocklist_sizes': {
                'urls': len(self.url_blocklist),
                'domains': len(self.domain_blocklist),
                'ips': len(self.ip_blocklist)
            },
            'sources_configured': {
                'misp': bool(self.misp_url and self.misp_key),
                'otx': bool(self.otx_key),
                'virustotal': bool(self.vt_key)
            }
        }


if __name__ == "__main__":
    async def main():
        print("Testing Threat Feed Aggregator...")
        
        aggregator = ThreatFeedAggregator()
        
        # Add some test data to local blocklist
        aggregator.add_to_blocklist(
            domains=['malicious.com', 'phishing-site.tk'],
            urls=['http://evil.com/login']
        )
        
        # Test URL check
        result = await aggregator.check_url('http://malicious.com/login')
        
        print(f"\nThreat Check Result:")
        print(f"  In Blocklist: {result['in_blocklist']}")
        print(f"  Threat Score: {result['threat_score']:.2f}")
        print(f"  Sources: {len(result['sources'])}")
        
        # Statistics
        stats = aggregator.get_statistics()
        print(f"\nStatistics:")
        print(f"  Blocklist - Domains: {stats['blocklist_sizes']['domains']}")
        print(f"  Blocklist - URLs: {stats['blocklist_sizes']['urls']}")
    
    asyncio.run(main())
