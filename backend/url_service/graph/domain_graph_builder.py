import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List

try:
    import dns.resolver
except Exception:  # pragma: no cover
    dns = None
try:
    import tldextract
except Exception:  # pragma: no cover
    tldextract = None
try:
    import whois
except Exception:  # pragma: no cover
    whois = None

from backend.storage.neo4j_client import neo4j_client


@dataclass
class DomainGraph:
    domain: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    features: Dict[str, float]


class DomainGraphBuilder:
    async def build_domain_graph(self, url_or_domain: str) -> DomainGraph:
        if tldextract is not None:
            extracted = tldextract.extract(url_or_domain)
            domain = '.'.join(p for p in [extracted.domain, extracted.suffix] if p) or url_or_domain
        else:
            host = url_or_domain.split('//')[-1].split('/')[0].split('@')[-1].split(':')[0]
            parts = [p for p in host.split('.') if p]
            domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host

        whois_data = await asyncio.to_thread(self._safe_whois, domain)
        ip_records = await asyncio.to_thread(self._safe_dns, domain)

        features = {
            'domain_age_days': float(self._domain_age_days(whois_data)),
            'ip_count': float(len(ip_records)),
            'ns_count': float(self._count_nameservers(whois_data)),
            'registrar_present': 1.0 if whois_data.get('registrar') else 0.0,
        }

        nodes = [{'type': 'Domain', 'name': domain, 'registrar': whois_data.get('registrar', ''), 'age_days': features['domain_age_days']}]
        edges = []
        for ip in ip_records:
            nodes.append({'type': 'IPAddress', 'address': ip})
            edges.append({'from': domain, 'to': ip, 'type': 'RESOLVES_TO', 'timestamp': datetime.now(timezone.utc).isoformat()})

        await self._persist_graph(domain, whois_data, ip_records)
        return DomainGraph(domain=domain, nodes=nodes, edges=edges, features=features)

    async def _persist_graph(self, domain: str, whois_data: Dict[str, Any], ip_records: List[str]) -> None:
        try:
            await neo4j_client.create_domain_node(domain, {'registrar': whois_data.get('registrar', ''), 'age_days': float(self._domain_age_days(whois_data))})
            for ip in ip_records:
                await neo4j_client.create_relationship(domain, ip, 'RESOLVES_TO')
        except Exception:
            return

    def _safe_whois(self, domain: str) -> Dict[str, Any]:
        if whois is None:
            return {}
        try:
            result = whois.whois(domain)
            return dict(result) if result else {}
        except Exception:
            return {}

    def _safe_dns(self, domain: str) -> List[str]:
        if dns is None:
            return []
        try:
            return [str(r) for r in dns.resolver.resolve(domain, 'A')]
        except Exception:
            return []

    def _domain_age_days(self, whois_data: Dict[str, Any]) -> int:
        created = whois_data.get('creation_date')
        if isinstance(created, list) and created:
            created = created[0]
        if not isinstance(created, datetime):
            return 0
        now = datetime.now(timezone.utc)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, int((now - created).total_seconds() // 86400))

    def _count_nameservers(self, whois_data: Dict[str, Any]) -> int:
        ns = whois_data.get('name_servers')
        if isinstance(ns, (list, tuple, set)):
            return len(ns)
        return 1 if isinstance(ns, str) and ns else 0
