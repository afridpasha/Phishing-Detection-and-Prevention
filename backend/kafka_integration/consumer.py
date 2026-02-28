try:
    from aiokafka import AIOKafkaConsumer
except Exception:  # pragma: no cover
    AIOKafkaConsumer = None
from ..api_gateway.config import settings
import json
import asyncio

class KafkaConsumer:
    def __init__(self, topic: str, handler_func):
        self.topic = topic
        self.handler_func = handler_func
        self.consumer = None
    
    async def start(self):
        """Start Kafka consumer"""
        if AIOKafkaConsumer is None:
            return
        self.consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            group_id=settings.KAFKA_CONSUMER_GROUP,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )
        await self.consumer.start()
        
        try:
            async for msg in self.consumer:
                await self.handler_func(msg.value)
        finally:
            await self.consumer.stop()
    
    async def stop(self):
        """Stop consumer"""
        if self.consumer:
            await self.consumer.stop()
