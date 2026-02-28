from fastapi import Request
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..config import settings


class JWTMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.public_paths = {'/health', '/docs', '/openapi.json', '/redoc'}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.public_paths:
            return await call_next(request)

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JSONResponse({'detail': 'Missing or invalid authorization header'}, status_code=401)

        token = auth_header.split(' ', 1)[1]
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            request.state.user = payload
        except JWTError:
            return JSONResponse({'detail': 'Invalid token'}, status_code=401)

        return await call_next(request)
