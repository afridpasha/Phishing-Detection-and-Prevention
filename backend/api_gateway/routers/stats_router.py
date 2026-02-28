from fastapi import APIRouter

from backend.storage.postgres_client import postgres_client

router = APIRouter(tags=['Statistics'])


@router.get('/statistics')
async def get_statistics() -> dict:
    defaults = {
        'total_requests': 0,
        'by_category': {'url': 0, 'sms': 0, 'email': 0, 'image': 0},
        'by_verdict': {'allow': 0, 'warn': 0, 'block': 0, 'emergency_block': 0},
        'avg_latency_per_category': {'url': 0.0, 'sms': 0.0, 'email': 0.0, 'image': 0.0},
        'model_accuracy_last_24h': 0.0,
        'top_phishing_domains': [],
        'top_attack_types': [],
    }
    try:
        stats = await postgres_client.get_statistics()
        defaults.update(stats)
    except Exception:
        pass
    return defaults
