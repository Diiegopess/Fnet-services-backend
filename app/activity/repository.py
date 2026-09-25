"""
Módulo de Repositorio para el Dominio de Actividad (Activity Logs).

Maneja el acceso a datos y consultas sobre la tabla 'activity_logs'.
"""

from datetime import datetime
from typing import Optional, Sequence
import uuid
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.activity.models import ActivityLog
from app.activity.schemas import ActivityLogCreate
from app.infrastructure.repositories.base import BaseRepository


class ActivityLogUpdateDummy(BaseModel):
    """Schema dummy necesario para cumplir con el contrato genérico de BaseRepository."""
    pass


class ActivityRepository(BaseRepository[ActivityLog, ActivityLogCreate, ActivityLogUpdateDummy]):
    def __init__(self, db: AsyncSession):
        super().__init__(model=ActivityLog, db=db)

    async def get_by_event_id(self, event_id: str) -> Optional[ActivityLog]:
        stmt = select(ActivityLog).where(ActivityLog.event_id == event_id)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_filtered_logs(
        self,
        skip: int = 0,
        limit: int = 50,
        event_type: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
    ) -> Sequence[ActivityLog]:
        stmt = select(ActivityLog)

        if event_type:
            stmt = stmt.where(ActivityLog.event_type == event_type)
        if user_id:
            stmt = stmt.where(ActivityLog.user_id == user_id)
        if from_date:
            stmt = stmt.where(ActivityLog.created_at >= from_date)
        if to_date:
            stmt = stmt.where(ActivityLog.created_at <= to_date)

        stmt = stmt.order_by(desc(ActivityLog.created_at)).offset(skip).limit(limit)
        result = await self.db.execute(stmt)
        return result.scalars().all()