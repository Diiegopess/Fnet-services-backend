"""
Módulo de Servicios para el Dominio de Actividad (Activity Logs).
"""

from datetime import datetime
from typing import Sequence
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.activity.models import ActivityLog
from app.activity.repository import ActivityRepository
from app.activity.schemas import ActivityLogCreate


async def record_activity_log(db: AsyncSession, log_in: ActivityLogCreate) -> ActivityLog:
    """
    Inserta un nuevo registro de actividad de forma inmutable utilizando el repositorio.
    """
    repo = ActivityRepository(db)
    return await repo.create(log_in)


async def get_activity_logs(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
    event_type: str | None = None,
    user_id: uuid.UUID | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
) -> Sequence[ActivityLog]:
    """
    Obtiene el historial de actividad con filtros opcionales ordenado descendentemente.
    """
    repo = ActivityRepository(db)
    return await repo.get_filtered_logs(
        skip=skip,
        limit=limit,
        event_type=event_type,
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
    )