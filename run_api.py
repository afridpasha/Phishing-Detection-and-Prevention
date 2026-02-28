import uvicorn
from backend.api_gateway.main import app
from backend.api_gateway.config import settings

if __name__ == '__main__':
    uvicorn.run(
        'backend.api_gateway.main:app',
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=settings.WORKERS,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
        reload=settings.API_ENV == 'development'
    )
