"""
Módulo de Controladores de Eventos (Event Handlers) del Dominio de Auditoría.
"""

from datetime import datetime, timezone
import logging
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit_service
from app.audit.schemas import AuditLogCreate
from app.core.events.base import DomainEvent

logger = logging.getLogger(__name__)


async def handle_audit_event(event: DomainEvent, db: AsyncSession) -> None:
    """
    Consume y procesa cualquier DomainEvent para registrarlo en audit_logs.
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
        "created_at": created_at_dt,  # <-- Sincronizado con Pydantic / DB
    }

    if event.metadata.ip_address:
        log_kwargs["ip_address"] = event.metadata.ip_address
    if event.metadata.user_agent:
        log_kwargs["user_agent"] = event.metadata.user_agent

    log_in = AuditLogCreate(**log_kwargs)

    try:
        await audit_service.record_audit_log(db=db, log_in=log_in)
        logger.info(f"[AUDIT_RECORDED] Evento {event.event_type} ({event.event_id}) auditado con éxito.")
    except Exception as e:
        logger.error(
            f"[AUDIT_RECORD_FAILED] Error al auditar evento {event.event_id}: {str(e)}",
            exc_info=True,
        )
        raise e