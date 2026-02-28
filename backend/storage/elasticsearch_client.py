from elasticsearch import AsyncElasticsearch

from backend.api_gateway.config import settings


class ElasticsearchClient:
    def __init__(self):
        self.client = AsyncElasticsearch(hosts=[f'http://{settings.ELASTICSEARCH_HOST}:{settings.ELASTICSEARCH_PORT}'])

    async def index_detection(self, doc: dict):
        await self.client.index(index='phishing-detections', document=doc)

    async def search_ioc(self, value: str):
        resp = await self.client.search(index='phishing-iocs', query={'match': {'value': value}}, size=5)
        hits = resp.get('hits', {}).get('hits', [])
        return [h.get('_source', {}) for h in hits]


elasticsearch_client = ElasticsearchClient()
