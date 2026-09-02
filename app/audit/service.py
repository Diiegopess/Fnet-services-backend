"""
Módulo de Servicios para el Dominio de Auditoría.
"""

from datetime import datetime
from typing import Sequence
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.models import AuditLog
from app.audit.repository import AuditRepository
from app.audit.schemas import AuditLogCreate


async def record_audit_log(db: AsyncSession, log_in: AuditLogCreate) -> AuditLog:
    """
    Inserta un nuevo registro de auditoría de forma inmutable utilizando el repositorio.
    """
    repo = AuditRepository(db)
    return await repo.create(log_in)


async def get_audit_logs(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
    event_type: str | None = None,
    user_id: uuid.UUID | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
) -> Sequence[AuditLog]:
    """
    Obtiene el historial de auditoría con filtros opcionales ordenado descendentemente.
    """
    repo = AuditRepository(db)
    return await repo.get_filtered_logs(
        skip=skip,
        limit=limit,
        event_type=event_type,
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
    )