"""
Adaptador de Redis para Caché, Revocación de Tokens y Event Streams.
"""

import logging
from typing import AsyncGenerator
import redis.asyncio as redis
from app.core.config import settings

logger = logging.getLogger(__name__)

# Pool global de conexiones resiliente
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    max_connections=settings.REDIS_POOL_SIZE,
    socket_timeout=5.0,
    socket_connect_timeout=5.0,
    retry_on_timeout=True,
)


def get_redis_client() -> redis.Redis:
    """Retorna una instancia de cliente de Redis conectada al pool global."""
    return redis.Redis(connection_pool=redis_pool)


async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    """Inyector de dependencia para FastApi (rutas HTTP)."""
    client = get_redis_client()
    try:
        yield client
    finally:
        await client.close()


async def close_redis_pool() -> None:
    """Cierra las conexiones del pool global durante el shutdown de la aplicación."""
    logger.info("Cerrando pool de conexiones Redis...")
    await redis_pool.disconnect()