try:
    from neo4j import AsyncGraphDatabase
except Exception:  # pragma: no cover
    AsyncGraphDatabase = None
from typing import Dict, List
from ..api_gateway.config import settings

class Neo4jClient:
    def __init__(self):
        if AsyncGraphDatabase is None:
            self.driver = None
        else:
            self.driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
            )
    
    async def create_domain_node(self, domain: str, properties: Dict):
        """Create or update domain node"""
        if self.driver is None:
            return
        async with self.driver.session() as session:
            await session.run('''
                MERGE (d:Domain {name: $domain})
                SET d += $properties
            ''', domain=domain, properties=properties)
    
    async def create_relationship(self, from_domain: str, to_ip: str, rel_type: str):
        """Create relationship between nodes"""
        if self.driver is None:
            return
        async with self.driver.session() as session:
            await session.run('''
                MATCH (d:Domain {name: $domain})
                MERGE (i:IPAddress {address: $ip})
                MERGE (d)-[r:%s {timestamp: datetime()}]->(i)
            ''' % rel_type, domain=from_domain, ip=to_ip)
    
    async def get_domain_neighbors(self, domain: str) -> List[Dict]:
        """Get neighboring nodes for domain"""
        if self.driver is None:
            return []
        async with self.driver.session() as session:
            result = await session.run('''
                MATCH (d:Domain {name: $domain})-[r]->(n)
                RETURN type(r) as rel_type, n.name as neighbor, labels(n) as labels
                LIMIT 100
            ''', domain=domain)
            return [dict(record) async for record in result]
    
    async def close(self):
        """Close driver"""
        if self.driver is not None:
            await self.driver.close()

# Global instance
neo4j_client = Neo4jClient()
