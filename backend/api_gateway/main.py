import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import structlog
from fastapi import FastAPI

from .middleware.auth import JWTMiddleware
from .middleware.rate_limiter import RateLimiterMiddleware
from .middleware.request_logger import RequestLoggerMiddleware
from .routers import email_router, feedback_router, image_router, sms_router, stats_router, url_router
from .routers import ioc_router, models_router

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info('Starting Phishing Shield 2.0...')
    app.state.started_at = time.time()

    from backend.email_service.service import load_email_models
    from backend.ensemble_engine.meta_learner import load_meta_learner
    from backend.image_service.service import load_image_models
    from backend.sms_service.service import load_sms_models
    from backend.url_service.service import load_url_models

    await load_url_models()
    await load_sms_models()
    await load_email_models()
    await load_image_models()
    await load_meta_learner()

    logger.info('All models loaded successfully')
    yield
    logger.info('Shutting down Phishing Shield 2.0...')


app = FastAPI(
    title='Phishing Shield 2.0',
    version='2.0.0',
    description='Real-Time AI/ML Phishing Detection & Prevention System',
    lifespan=lifespan,
)

app.add_middleware(RequestLoggerMiddleware)
app.add_middleware(JWTMiddleware)
app.add_middleware(RateLimiterMiddleware)

app.include_router(url_router.router, prefix='/api/v2')
app.include_router(sms_router.router, prefix='/api/v2')
app.include_router(email_router.router, prefix='/api/v2')
app.include_router(image_router.router, prefix='/api/v2')
app.include_router(stats_router.router, prefix='/api/v2')
app.include_router(feedback_router.router, prefix='/api/v2')
app.include_router(models_router.router, prefix='/api/v2')
app.include_router(ioc_router.router, prefix='/api/v2')


@app.get('/health')
async def health():
    started = getattr(app.state, 'started_at', time.time())
    return {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '2.0.0',
        'models_loaded': True,
        'uptime_seconds': max(0.0, time.time() - started),
    }
