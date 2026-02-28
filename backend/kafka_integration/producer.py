try:
    from aiokafka import AIOKafkaProducer
except Exception:  # pragma: no cover
    AIOKafkaProducer = None
from ..api_gateway.config import settings
import json
from typing import Dict

class KafkaProducer:
    def __init__(self):
        self.producer = None
    
    async def start(self):
        """Start Kafka producer"""
        if AIOKafkaProducer is None:
            self.producer = None
            return
        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        await self.producer.start()
    
    async def publish_for_analysis(self, topic: str, message: Dict):
        """Publish message for analysis"""
        if not self.producer:
            await self.start()
            if not self.producer:
                return
        
        await self.producer.send(topic, value=message)
    
    async def publish_result(self, result: Dict):
        """Publish detection result"""
        if not self.producer:
            await self.start()
            if not self.producer:
                return
        
        await self.producer.send('detection.results', value=result)
    
    async def publish_ioc(self, ioc_data: Dict):
        """Publish IOC update"""
        if not self.producer:
            await self.start()
            if not self.producer:
                return
        
        await self.producer.send('ioc.updates', value=ioc_data)
    
    async def stop(self):
        """Stop producer"""
        if self.producer:
            await self.producer.stop()

# Global instance
kafka_producer = KafkaProducer()
