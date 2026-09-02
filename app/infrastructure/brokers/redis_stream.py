"""
Adaptador de Broker de Eventos basado en Redis Streams.
"""

import json
import logging
from datetime import datetime
from redis.asyncio import Redis

from app.core.events.base import DomainEvent
from app.core.events.interfaces import IEventPublisher

logger = logging.getLogger(__name__)


class RedisStreamPublisher(IEventPublisher):
    """Implementación de IEventPublisher utilizando Redis Streams (XADD)."""

    def __init__(self, redis_client: Redis):
        self.redis_client = redis_client

    async def publish(self, stream_or_topic: str, event: DomainEvent) -> str:
        try:
            # Garantizar que occurred_at sea un string ISO
            occurred_at_str = (
                event.occurred_at.isoformat()
                if isinstance(event.occurred_at, datetime)
                else str(event.occurred_at)
            )

            # Extracción segura de metadatos (Pydantic v2 / v1)
            if hasattr(event.metadata, "model_dump"):
                metadata_dict = event.metadata.model_dump()
            elif hasattr(event.metadata, "dict"):
                metadata_dict = event.metadata.dict()
            elif isinstance(event.metadata, dict):
                metadata_dict = event.metadata
            else:
                metadata_dict = {}

            event_data = {
                "event_id": str(event.event_id),
                "event_type": str(event.event_type),
                "occurred_at": occurred_at_str,
                "metadata": json.dumps(metadata_dict),
                "payload": json.dumps(event.payload if event.payload is not None else {}),
            }

            message_id = await self.redis_client.xadd(
                name=stream_or_topic,
                fields=event_data,
                maxlen=100000,
                approximate=True,
            )

            # Decodificar el message_id si Redis lo retorna como bytes
            msg_id_str = message_id.decode("utf-8") if isinstance(message_id, bytes) else str(message_id)

            logger.info(
                f"[EVENT_PUBLISHED] '{event.event_type}' publicado en '{stream_or_topic}' con ID: {msg_id_str}"
            )
            return msg_id_str

        except Exception as e:
            logger.error(
                f"[EVENT_PUBLISH_ERROR] Fallo al publicar '{event.event_type}' en '{stream_or_topic}': {str(e)}",
                exc_info=True,
            )
            raise e