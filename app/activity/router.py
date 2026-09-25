"""
Rutas HTTP API del Módulo de Actividad (Activity Logs).
"""

from datetime import datetime
from typing import Any, List, Optional
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.activity import service as activity_service
from app.activity.dependencies import require_activity_permission
from app.activity.permissions import ActivityPermission
from app.activity.schemas import ActivityLogResponse
from app.core.rbac.context import AuthenticatedUser
from app.infrastructure.db.database import get_db

router = APIRouter(prefix="/activities", tags=["Activity Logs"])


@router.get(
    "/logs",
    response_model=List[ActivityLogResponse],
    status_code=status.HTTP_200_OK,
    summary="Consultar logs de actividad del sistema",
    description="Permite a los usuarios autorizados consultar el historial de actividad y eventos del sistema.",
)
async def list_activity_logs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=200),
    event_type: Optional[str] = Query(default=None, description="Filtrar por tipo de evento"),
    user_id: Optional[uuid.UUID] = Query(default=None, description="Filtrar por ID de usuario"),
    from_date: Optional[datetime] = Query(default=None, description="Filtrar eventos desde esta fecha/hora"),
    to_date: Optional[datetime] = Query(default=None, description="Filtrar eventos hasta esta fecha/hora"),
    current_user: AuthenticatedUser = Depends(require_activity_permission(ActivityPermission.READ)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    return await activity_service.get_activity_logs(
        db=db,
        skip=skip,
        limit=limit,
        event_type=event_type,
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
    )