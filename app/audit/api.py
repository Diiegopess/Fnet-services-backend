"""
API Pública del Módulo de Auditoría.

Punto único de contacto interno para otros módulos del backend.
"""

from datetime import datetime
from typing import Any, Optional, Sequence
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit_service
from app.audit.schemas import AuditLogCreate, AuditLogResponse


class AuditAPI:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log_event(
        self,
        event_type: str,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        payload: Optional[dict[str, Any]] = None,
    ) -> AuditLogResponse:
        """
        Registra directamente un evento en la bitácora de auditoría sin
        requerir que otros módulos importen esquemas internos de audit.
        """
        log_in = AuditLogCreate(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            payload=payload or {},
        )
        log = await audit_service.record_audit_log(self.db, log_in)
        return AuditLogResponse.model_validate(log)

    async def query_logs(
        self,
        skip: int = 0,
        limit: int = 50,
        event_type: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
    ) -> Sequence[AuditLogResponse]:
        """Consulta registros de auditoría retornando DTOs Pydantic."""
        logs = await audit_service.get_audit_logs(
            db=self.db,
            skip=skip,
            limit=limit,
            event_type=event_type,
            user_id=user_id,
            from_date=from_date,
            to_date=to_date,
        )
        return [AuditLogResponse.model_validate(log) for log in logs]