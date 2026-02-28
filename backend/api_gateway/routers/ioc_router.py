from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from backend.kafka_integration.producer import kafka_producer
from backend.storage.postgres_client import postgres_client
from backend.storage.redis_client import redis_client

router = APIRouter(tags=['IOC'])
_ioc_memory = {}


class IOCSubmitRequest(BaseModel):
    type: str = Field(pattern='^(url|domain|ip|email|hash)$')
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = 'user'


@router.post('/ioc/submit')
async def submit_ioc(payload: IOCSubmitRequest):
    data = payload.model_dump()
    _ioc_memory[data['value']] = data

    try:
        await postgres_client.store_ioc(data['type'], data['value'], data['confidence'], data['source'])
    except Exception:
        pass

    try:
        await redis_client.cache_ioc(data['type'], data['value'], data)
    except Exception:
        pass

    try:
        await kafka_producer.publish_ioc(data)
    except Exception:
        pass
    return {'status': 'success', 'ioc': data}


@router.get('/ioc/lookup')
async def lookup_ioc(value: str = Query(...)):
    for ioc_type in ['domain', 'url', 'ip', 'email', 'hash']:
        try:
            cached = await redis_client.get_ioc(ioc_type, value)
        except Exception:
            cached = None
        if cached:
            return {'found': True, 'source': 'redis', 'ioc': cached}

    in_memory = _ioc_memory.get(value)
    if in_memory:
        return {'found': True, 'source': 'memory', 'ioc': in_memory}

    try:
        ioc = await postgres_client.get_ioc_by_value(value)
    except Exception:
        ioc = None

    if ioc:
        try:
            await redis_client.cache_ioc(ioc['ioc_type'], ioc['value'], ioc)
        except Exception:
            pass
        return {'found': True, 'source': 'postgres', 'ioc': ioc}

    return {'found': False, 'ioc': None}
