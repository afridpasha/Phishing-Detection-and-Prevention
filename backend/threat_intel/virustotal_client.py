try:
    import vt
except Exception:  # pragma: no cover
    vt = None
from typing import Dict, Optional
from ..api_gateway.config import settings

class VirusTotalClient:
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.client = vt.Client(self.api_key) if (self.api_key and vt is not None) else None
    
    async def check_url(self, url: str) -> Dict:
        """Check URL against VirusTotal"""
        if not self.client:
            return {'in_virustotal': False, 'detection_ratio': 0.0}
        
        try:
            url_id = vt.url_id(url)
            url_obj = await self.client.get_object_async(f"/urls/{url_id}")
            
            stats = url_obj.last_analysis_stats
            total = sum(stats.values())
            malicious = stats.get('malicious', 0)
            
            return {
                'in_virustotal': True,
                'detection_ratio': malicious / total if total > 0 else 0.0,
                'malicious_count': malicious,
                'total_engines': total,
                'reputation': url_obj.reputation
            }
        except:
            return {'in_virustotal': False, 'detection_ratio': 0.0}
    
    async def check_domain(self, domain: str) -> Dict:
        """Check domain against VirusTotal"""
        if not self.client:
            return {'in_virustotal': False, 'reputation': 0}
        
        try:
            domain_obj = await self.client.get_object_async(f"/domains/{domain}")
            return {
                'in_virustotal': True,
                'reputation': domain_obj.reputation,
                'categories': domain_obj.categories
            }
        except:
            return {'in_virustotal': False, 'reputation': 0}
    
    def __del__(self):
        if self.client:
            self.client.close()
