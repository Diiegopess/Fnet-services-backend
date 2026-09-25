"""
API Pública del Módulo de Actividad (Activity Logs).

Punto único de contacto interno para otros módulos del backend.
"""

from datetime import datetime, timezone
from typing import Any, Optional, Sequence
import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.activity import service as activity_service
from app.activity.schemas import ActivityLogCreate, ActivityLogResponse


class ActivityAPI:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log_event(
        self,
        event_type: str,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        payload: Optional[dict[str, Any]] = None,
    ) -> ActivityLogResponse:
        """
        Registra directamente un evento en la bitácora de actividad sin
        requerir que otros módulos importen esquemas internos de activity.
        """
        log_in = ActivityLogCreate(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address or "unknown",
            user_agent=user_agent or "unknown",
            payload=payload or {},
            occurred_at=datetime.now(timezone.utc),
        )
        log = await activity_service.record_activity_log(self.db, log_in)
        return ActivityLogResponse.model_validate(log)

    async def query_logs(
        self,
        skip: int = 0,
        limit: int = 50,
        event_type: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
    ) -> Sequence[ActivityLogResponse]:
        """Consulta registros de actividad retornando DTOs Pydantic."""
        logs = await activity_service.get_activity_logs(
            db=self.db,
            skip=skip,
            limit=limit,
            event_type=event_type,
            user_id=user_id,
            from_date=from_date,
            to_date=to_date,
        )
        return [ActivityLogResponse.model_validate(log) for log in logs]