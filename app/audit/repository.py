"""
Módulo de Repositorio para el Dominio de Auditoría.

Maneja el acceso a datos y consultas sobre la tabla 'audit_logs'.
"""

from datetime import datetime
from typing import Optional, Sequence
import uuid
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.models import AuditLog
from app.audit.schemas import AuditLogCreate
from app.infrastructure.repositories.base import BaseRepository


class AuditLogUpdateDummy(BaseModel):
    """Schema dummy necesario para cumplir con el contrato genérico de BaseRepository."""
    pass


class AuditRepository(BaseRepository[AuditLog, AuditLogCreate, AuditLogUpdateDummy]):
    def __init__(self, db: AsyncSession):
        super().__init__(model=AuditLog, db=db)

    async def get_by_event_id(self, event_id: str) -> Optional[AuditLog]:
        stmt = select(AuditLog).where(AuditLog.event_id == event_id)
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
    ) -> Sequence[AuditLog]:
        stmt = select(AuditLog)

        if event_type:
            stmt = stmt.where(AuditLog.event_type == event_type)
        if user_id:
            stmt = stmt.where(AuditLog.user_id == user_id)
        if from_date:
            stmt = stmt.where(AuditLog.created_at >= from_date)
        if to_date:
            stmt = stmt.where(AuditLog.created_at <= to_date)

        stmt = stmt.order_by(desc(AuditLog.created_at)).offset(skip).limit(limit)
        result = await self.db.execute(stmt)
        return result.scalars().all()