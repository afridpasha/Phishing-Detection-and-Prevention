import time

try:
    import redis.asyncio as redis
except Exception:  # pragma: no cover
    redis = None
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..config import settings


class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.redis_client = None
        self._local = {}
        self._last_connect_failure = 0.0

    async def _get_client(self):
        if self.redis_client is not None:
            return self.redis_client
        if redis is None:
            return None
        now = time.time()
        if now - self._last_connect_failure < 5.0:
            return None
        try:
            self.redis_client = await redis.from_url(
                f'redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}:{settings.REDIS_PORT}',
                socket_connect_timeout=0.2,
                socket_timeout=0.2,
                retry_on_timeout=False,
            )
        except Exception:
            self.redis_client = None
            self._last_connect_failure = now
        return self.redis_client

    def _tier_limit(self, api_key: str) -> int:
        if api_key in settings.enterprise_keys or api_key.startswith('ent_'):
            return 10000
        return settings.REDIS_RATE_LIMIT_PER_MIN

    async def dispatch(self, request: Request, call_next):
        if request.url.path == '/health':
            return await call_next(request)

        api_key = request.headers.get(settings.API_KEY_HEADER, 'default')
        limit = self._tier_limit(api_key)
        reset_at = int(time.time()) + 60
        count = 0

        client = await self._get_client()
        rate_key = f'ratelimit:apikey:{api_key}'

        if client:
            try:
                count = int(await client.get(rate_key) or 0)
                if count >= limit:
                    resp = JSONResponse({'detail': 'Rate limit exceeded'}, status_code=429)
                    resp.headers['X-RateLimit-Remaining'] = '0'
                    resp.headers['X-RateLimit-Reset'] = str(reset_at)
                    return resp

                pipe = client.pipeline()
                pipe.incr(rate_key)
                pipe.expire(rate_key, 60)
                await pipe.execute()
                count += 1
            except Exception:
                client = None
                self.redis_client = None
                self._last_connect_failure = time.time()

        if not client:
            window = int(time.time() // 60)
            key = f'{api_key}:{window}'
            count = self._local.get(key, 0)
            if count >= limit:
                resp = JSONResponse({'detail': 'Rate limit exceeded'}, status_code=429)
                resp.headers['X-RateLimit-Remaining'] = '0'
                resp.headers['X-RateLimit-Reset'] = str(reset_at)
                return resp
            self._local[key] = count + 1
            count += 1

        response = await call_next(request)
        response.headers['X-RateLimit-Remaining'] = str(max(0, limit - count))
        response.headers['X-RateLimit-Reset'] = str(reset_at)
        return response
