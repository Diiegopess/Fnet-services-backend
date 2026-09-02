"""
Fábrica de Inyección de Brokers de Mensajería.
"""

from app.core.config import settings
from app.core.events.interfaces import IEventPublisher
from app.infrastructure.brokers.redis_stream import RedisStreamPublisher
from app.infrastructure.cache.redis import get_redis_client


def get_event_publisher() -> IEventPublisher:
    """Retorna la implementación concreta de IEventPublisher configurada."""
    broker_type = settings.BROKER_TYPE.upper()

    if broker_type == "REDIS":
        redis_client = get_redis_client()
        return RedisStreamPublisher(redis_client=redis_client)

    raise ValueError(f"Tipo de broker no soportado o no configurado: {broker_type}")