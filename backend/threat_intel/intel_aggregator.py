from typing import Dict

from .misp_client import MISPClient
from .otx_client import OTXClient
from .phishtank_client import PhishTankClient
from .urlhaus_client import URLHausClient
from .virustotal_client import VirusTotalClient


class ThreatIntelAggregator:
    def __init__(self):
        self.vt_client = VirusTotalClient()
        self.misp = MISPClient()
        self.otx = OTXClient()
        self.urlhaus = URLHausClient()
        self.phishtank = PhishTankClient()

    async def check_url(self, url: str) -> Dict:
        vt_result = await self.vt_client.check_url(url)
        misp_result = await self.misp.lookup(url)
        otx_result = await self.otx.lookup_url(url)
        urlhaus_result = await self.urlhaus.lookup(url)
        phishtank_result = await self.phishtank.lookup(url)

        threat_score = max(
            float(vt_result.get('detection_ratio', 0.0)),
            float(misp_result.get('score', 0.0)),
            float(otx_result.get('score', 0.0)),
            float(urlhaus_result.get('score', 0.0)),
            float(phishtank_result.get('score', 0.0)),
        )

        in_any = any(
            [
                vt_result.get('in_virustotal'),
                misp_result.get('in_misp'),
                otx_result.get('in_otx'),
                urlhaus_result.get('in_urlhaus'),
                phishtank_result.get('in_phishtank'),
            ]
        )

        return {
            'threat_score': float(threat_score),
            'virustotal': vt_result,
            'misp': misp_result,
            'otx': otx_result,
            'urlhaus': urlhaus_result,
            'phishtank': phishtank_result,
            'in_any_feed': bool(in_any),
        }

    async def check_domain(self, domain: str) -> Dict:
        vt_result = await self.vt_client.check_domain(domain)
        threat_score = 0.0
        if vt_result.get('in_virustotal') and vt_result.get('reputation', 0) < -50:
            threat_score = 0.8

        return {'threat_score': threat_score, 'virustotal': vt_result}
