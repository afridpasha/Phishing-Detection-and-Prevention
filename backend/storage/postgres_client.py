try:
    import asyncpg
except Exception:  # pragma: no cover - fallback for environments without DB deps
    asyncpg = None
from typing import Dict, List, Optional
from ..api_gateway.config import settings
import json
import time

class PostgresClient:
    def __init__(self):
        self.pool: Optional[object] = None
        self._memory_results: List[Dict] = []
        self._memory_iocs: Dict[str, Dict] = {}
        self._last_connect_failure: float = 0.0
    
    async def connect(self):
        """Create connection pool"""
        if asyncpg is None:
            self.pool = None
            return
        now = time.time()
        if now - self._last_connect_failure < 5.0:
            return
        try:
            self.pool = await asyncpg.create_pool(
                host=settings.POSTGRES_HOST,
                port=settings.POSTGRES_PORT,
                user=settings.POSTGRES_USER,
                password=settings.POSTGRES_PASSWORD,
                database=settings.POSTGRES_DB,
                min_size=5,
                max_size=settings.POSTGRES_POOL_SIZE,
                timeout=1.0,
            )
        except Exception:
            self.pool = None
            self._last_connect_failure = now
    
    async def store_detection_result(self, result: Dict):
        """Store detection result in database"""
        if not self.pool:
            await self.connect()

        if self.pool:
            try:
                async with self.pool.acquire() as conn:
                    await conn.execute('''
                        INSERT INTO detection_results 
                        (request_id, timestamp, input_type, final_score, risk_level, action, 
                         confidence, latency_ms, model_scores, shap_values, indicators, metadata)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    ''', 
                        result['request_id'],
                        result['timestamp'],
                        result['input_type'],
                        result['final_score'],
                        result['risk_level'],
                        result['action'],
                        result['confidence'],
                        result['latency_ms'],
                        json.dumps(result['model_scores']),
                        json.dumps(result.get('shap_values', {})),
                        result.get('indicators', []),
                        json.dumps(result.get('metadata', {}))
                    )
                return
            except Exception:
                self.pool = None
                self._last_connect_failure = time.time()

        self._memory_results.append(dict(result))
    
    async def store_ioc(self, ioc_type: str, value: str, confidence: float, source: str):
        """Store IOC in database"""
        if not self.pool:
            await self.connect()

        if self.pool:
            try:
                async with self.pool.acquire() as conn:
                    await conn.execute('''
                        INSERT INTO iocs (ioc_type, value, confidence, source)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT (value) DO UPDATE SET
                            last_seen = NOW(),
                            confidence = GREATEST(iocs.confidence, EXCLUDED.confidence)
                    ''', ioc_type, value, confidence, source)
                return
            except Exception:
                self.pool = None
                self._last_connect_failure = time.time()

        existing = self._memory_iocs.get(value)
        if existing:
            existing['confidence'] = max(existing.get('confidence', 0.0), confidence)
            existing['last_seen'] = 'now'
        else:
            self._memory_iocs[value] = {
                'ioc_type': ioc_type,
                'value': value,
                'confidence': confidence,
                'source': source,
                'first_seen': 'now',
                'last_seen': 'now',
            }
    
    async def get_statistics(self) -> Dict:
        """Get system statistics"""
        if not self.pool:
            await self.connect()

        if self.pool:
            try:
                async with self.pool.acquire() as conn:
                    total = await conn.fetchval('SELECT COUNT(*) FROM detection_results')
                    by_category = await conn.fetch('''
                        SELECT input_type, COUNT(*) as count 
                        FROM detection_results 
                        GROUP BY input_type
                    ''')
                    by_verdict = await conn.fetch('''
                        SELECT action, COUNT(*) as count 
                        FROM detection_results 
                        GROUP BY action
                    ''')
                    avg_latency = await conn.fetch('''
                        SELECT input_type, AVG(latency_ms) as avg_latency
                        FROM detection_results
                        GROUP BY input_type
                    ''')
                    top_domains = await conn.fetch('''
                        SELECT metadata->>'final_destination' as domain, COUNT(*) as c
                        FROM detection_results
                        WHERE input_type='url'
                        GROUP BY domain
                        ORDER BY c DESC
                        LIMIT 10
                    ''')
                    
                    return {
                        'total_requests': total,
                        'by_category': {row['input_type']: row['count'] for row in by_category},
                        'by_verdict': {row['action']: row['count'] for row in by_verdict},
                        'avg_latency_per_category': {row['input_type']: float(row['avg_latency'] or 0.0) for row in avg_latency},
                        'model_accuracy_last_24h': 0.0,
                        'top_phishing_domains': [row['domain'] for row in top_domains if row['domain']],
                        'top_attack_types': [],
                    }
            except Exception:
                self.pool = None
                self._last_connect_failure = time.time()

        total = len(self._memory_results)
        by_category: Dict[str, int] = {}
        by_verdict: Dict[str, int] = {}
        latency_sum: Dict[str, float] = {}
        latency_count: Dict[str, int] = {}
        domains: Dict[str, int] = {}

        for row in self._memory_results:
            input_type = row.get('input_type')
            action = row.get('action')
            if input_type:
                by_category[input_type] = by_category.get(input_type, 0) + 1
                latency_sum[input_type] = latency_sum.get(input_type, 0.0) + float(row.get('latency_ms', 0.0))
                latency_count[input_type] = latency_count.get(input_type, 0) + 1
            if action:
                by_verdict[action] = by_verdict.get(action, 0) + 1
            if input_type == 'url':
                metadata = row.get('metadata') or {}
                domain = metadata.get('final_destination') if isinstance(metadata, dict) else None
                if domain:
                    domains[domain] = domains.get(domain, 0) + 1

        avg_latency_per_category = {}
        for k, total_latency in latency_sum.items():
            avg_latency_per_category[k] = total_latency / max(latency_count.get(k, 1), 1)

        top_phishing_domains = sorted(domains.keys(), key=lambda d: domains[d], reverse=True)[:10]

        return {
            'total_requests': total,
            'by_category': by_category,
            'by_verdict': by_verdict,
            'avg_latency_per_category': avg_latency_per_category,
            'model_accuracy_last_24h': 0.0,
            'top_phishing_domains': top_phishing_domains,
            'top_attack_types': [],
        }

    async def get_ioc_by_value(self, value: str) -> Optional[Dict]:
        """Lookup IOC by value from DB, with in-memory fallback."""
        if not self.pool:
            await self.connect()

        if self.pool:
            try:
                async with self.pool.acquire() as conn:
                    row = await conn.fetchrow(
                        'SELECT ioc_type, value, confidence, source, first_seen, last_seen FROM iocs WHERE value=$1',
                        value
                    )
                return dict(row) if row else None
            except Exception:
                self.pool = None
                self._last_connect_failure = time.time()

        return self._memory_iocs.get(value)
    
    async def close(self):
        """Close connection pool"""
        if self.pool:
            try:
                await self.pool.close()
            except Exception:
                pass

# Global instance
postgres_client = PostgresClient()
