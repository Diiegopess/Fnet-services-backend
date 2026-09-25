"""
Módulo de Controladores de Eventos (Event Handlers) del Dominio de Actividad (Activity Logs).
"""

from datetime import datetime, timezone
import logging
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.activity import service as activity_service
from app.activity.schemas import ActivityLogCreate
from app.core.events.base import DomainEvent

logger = logging.getLogger(__name__)


async def handle_activity_event(event: DomainEvent, db: AsyncSession) -> None:
    """
    Consume y procesa cualquier DomainEvent para registrarlo en activity_logs.
    Prioriza el actor_id de metadata y usa payload.user_id como fallback.
    """
    user_id_raw = event.metadata.actor_id or event.payload.get("user_id")
    user_uuid: uuid.UUID | None = None

    if user_id_raw:
        try:
            user_uuid = uuid.UUID(str(user_id_raw))
        except ValueError:
            user_uuid = None

    try:
        created_at_dt = datetime.fromisoformat(event.occurred_at)
    except Exception:
        created_at_dt = datetime.now(timezone.utc)

    # Construir kwargs filtrando nulos para que apliquen los valores por defecto
    log_kwargs = {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "user_id": user_uuid,
        "payload": event.payload,
        "created_at": created_at_dt,
    }

    if event.metadata.ip_address:
        log_kwargs["ip_address"] = event.metadata.ip_address
    if event.metadata.user_agent:
        log_kwargs["user_agent"] = event.metadata.user_agent

    log_in = ActivityLogCreate(**log_kwargs)

    try:
        await activity_service.record_activity_log(db=db, log_in=log_in)
        logger.info(f"[ACTIVITY_RECORDED] Evento {event.event_type} ({event.event_id}) registrado con éxito.")
    except Exception as e:
        logger.error(
            f"[ACTIVITY_RECORD_FAILED] Error al registrar evento {event.event_id}: {str(e)}",
            exc_info=True,
        )
        raise e