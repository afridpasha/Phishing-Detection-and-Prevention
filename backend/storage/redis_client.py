try:
    import redis.asyncio as redis
except Exception:  # pragma: no cover
    redis = None
from typing import Optional, Dict
from ..api_gateway.config import settings
import json
import time

class RedisClient:
    def __init__(self):
        self.client: Optional[object] = None
        self._memory_cache: Dict[str, str] = {}
        self._memory_stats: Dict[str, int] = {}
        self._last_connect_failure: float = 0.0
    
    async def connect(self):
        """Connect to Redis"""
        if redis is None:
            return
        now = time.time()
        if now - self._last_connect_failure < 5.0:
            return
        try:
            self.client = await redis.from_url(
                f"redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}:{settings.REDIS_PORT}",
                socket_connect_timeout=0.2,
                socket_timeout=0.2,
                retry_on_timeout=False,
            )
        except Exception:
            self.client = None
            self._last_connect_failure = now
    
    async def cache_ioc(self, ioc_type: str, value: str, data: Dict, ttl: int = None):
        """Cache IOC data"""
        if not self.client:
            await self.connect()
        
        key = f"ioc:{ioc_type}:{value}"
        payload = json.dumps(data)
        if self.client:
            try:
                await self.client.setex(
                    key,
                    ttl or settings.REDIS_IOC_TTL_SECONDS,
                    payload
                )
                return
            except Exception:
                self.client = None
                self._last_connect_failure = time.time()
        self._memory_cache[key] = payload
    
    async def get_ioc(self, ioc_type: str, value: str) -> Optional[Dict]:
        """Get cached IOC data"""
        if not self.client:
            await self.connect()
        
        key = f"ioc:{ioc_type}:{value}"
        if self.client:
            try:
                data = await self.client.get(key)
                return json.loads(data) if data else None
            except Exception:
                self.client = None
                self._last_connect_failure = time.time()
        data = self._memory_cache.get(key)
        return json.loads(data) if data else None
    
    async def cache_analysis(self, request_id: str, result: Dict, ttl: int = 1800):
        """Cache analysis result"""
        if not self.client:
            await self.connect()
        
        key = f"analysis:{request_id}"
        payload = json.dumps(result)
        if self.client:
            try:
                await self.client.setex(key, ttl, payload)
                return
            except Exception:
                self.client = None
                self._last_connect_failure = time.time()
        self._memory_cache[key] = payload
    
    async def increment_stats(self, stat_key: str):
        """Increment statistics counter"""
        if not self.client:
            await self.connect()
        
        key = f"stats:{stat_key}"
        if self.client:
            try:
                await self.client.incr(key)
                return
            except Exception:
                self.client = None
                self._last_connect_failure = time.time()
        self._memory_stats[key] = self._memory_stats.get(key, 0) + 1
    
    async def close(self):
        """Close connection"""
        if self.client:
            try:
                await self.client.close()
            except Exception:
                pass

# Global instance
redis_client = RedisClient()
