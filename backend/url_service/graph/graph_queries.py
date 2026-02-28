from typing import Dict

from backend.storage.neo4j_client import neo4j_client


async def get_domain_neighbor_stats(domain: str) -> Dict[str, float]:
    try:
        neighbors = await neo4j_client.get_domain_neighbors(domain)
    except Exception:
        neighbors = []
    rel_types = [n.get('rel_type', '') for n in neighbors]
    return {
        'neighbor_count': float(len(neighbors)),
        'resolves_to_count': float(sum(1 for t in rel_types if t == 'RESOLVES_TO')),
        'ssl_edge_count': float(sum(1 for t in rel_types if t == 'USES_SSL')),
    }
