"""
Módulo de Consumo en Segundo Plano basado en Redis Streams (Desacoplado y Robusto).
"""

import asyncio
import json
import logging
from typing import Any, Dict
from redis.asyncio import Redis
from redis.exceptions import ResponseError

from app.core.config import settings
from app.core.events.base import DomainEvent, EventMetadata
from app.core.events.router import event_router
from app.infrastructure.cache.redis import get_redis_client
from app.infrastructure.db.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class RedisStreamConsumer:
    """Consumidor asíncrono agnóstico a la lógica de negocio."""

    def __init__(self):
        self.redis: Redis = get_redis_client()
        self.is_running: bool = False
        self.consumer_name: str = getattr(settings, "REDIS_CONSUMER_NAME", "fastapi_worker_1")
        self.group_name: str = getattr(settings, "REDIS_CONSUMER_GROUP", "group:fastapi_backend")

    async def _ensure_consumer_groups(self) -> None:
        """Asegura que el grupo de consumidores existe en todos los streams configurados."""
        streams = [
            getattr(settings, "AUTH_STREAM_NAME", "stream:auth"),
            getattr(settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"),
        ]

        for stream in streams:
            try:
                # Se utiliza el id="0" para procesar eventos históricos o "$" para eventos nuevos desde el inicio
                await self.redis.xgroup_create(
                    name=stream, groupname=self.group_name, id="0", mkstream=True
                )
                logger.info(f"[CONSUMER_INIT] Grupo '{self.group_name}' verificado en stream '{stream}'.")
            except ResponseError as e:
                if "BUSYGROUP" in str(e):
                    pass
                else:
                    logger.error(f"[CONSUMER_ERROR] Error al crear grupo '{self.group_name}' en '{stream}': {str(e)}")

    async def start(self) -> None:
        """Inicia el ciclo continuo de escucha y despacho de eventos."""
        await self._ensure_consumer_groups()
        self.is_running = True
        logger.info(f"[CONSUMER_STARTED] Worker '{self.consumer_name}' escuchando eventos en grupo '{self.group_name}'...")

        streams_to_read = {
            getattr(settings, "AUTH_STREAM_NAME", "stream:auth"): ">",
            getattr(settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"): ">",
        }

        while self.is_running:
            try:
                # XREADGROUP bloquea la llamada por 2000ms si no hay mensajes nuevos
                response = await self.redis.xreadgroup(
                    groupname=self.group_name,
                    consumername=self.consumer_name,
                    streams=streams_to_read,
                    count=10,
                    block=2000,
                )

                if not response:
                    await asyncio.sleep(0.1)
                    continue

                for stream_name, messages in response:
                    stream_str = stream_name.decode("utf-8") if isinstance(stream_name, bytes) else stream_name

                    for message_id, raw_data in messages:
                        msg_id_str = message_id.decode("utf-8") if isinstance(message_id, bytes) else message_id
                        
                        await self._process_message(
                            stream_name=stream_str,
                            message_id=msg_id_str,
                            raw_data=raw_data,
                        )

            except asyncio.CancelledError:
                logger.info("[CONSUMER_STOPPING] Tarea de consumidor cancelada.")
                break
            except Exception as e:
                logger.error(f"[CONSUMER_LOOP_ERROR] Error en el ciclo de consumo: {str(e)}", exc_info=True)
                await asyncio.sleep(1)

    async def _process_message(self, stream_name: str, message_id: str, raw_data: Dict[Any, Any]) -> None:
        """Parsea el evento y delega el despacho al EventRouter de la aplicación."""
        try:
            # Decodificar llaves/valores si vienen en formato bytes
            clean_data = {}
            for k, v in raw_data.items():
                key_str = k.decode("utf-8") if isinstance(k, bytes) else k
                val_str = v.decode("utf-8") if isinstance(v, bytes) else v
                clean_data[key_str] = val_str

            metadata_dict = json.loads(clean_data.get("metadata", "{}"))
            payload_dict = json.loads(clean_data.get("payload", "{}"))

            event = DomainEvent(
                event_id=clean_data.get("event_id"),
                event_type=clean_data.get("event_type"),
                occurred_at=clean_data.get("occurred_at"),
                metadata=EventMetadata(**metadata_dict),
                payload=payload_dict,
            )

            # Instanciación limpia de DB AsyncSession por lote/evento
            async with AsyncSessionLocal() as db:
                await event_router.dispatch(event=event, db=db)

            # Confirmar mensaje procesado exitosamente
            await self.redis.xack(stream_name, self.group_name, message_id)

        except Exception as e:
            logger.error(
                f"[CONSUMER_PROCESS_ERROR] Fallo al procesar mensaje {message_id} en {stream_name}: {str(e)}",
                exc_info=True,
            )

    async def stop(self) -> None:
        """Detiene la bandera del ciclo del consumidor."""
        self.is_running = False
        logger.info("[CONSUMER_STOPPED] Worker de Redis Streams detenido.")