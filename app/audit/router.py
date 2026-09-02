"""
Rutas HTTP API del Módulo de Auditoría.
"""

from datetime import datetime
from typing import Any
import uuid
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit_service
from app.audit.dependencies import require_audit_access
from app.audit.schemas import AuditLogResponse
from app.core.rbac.context import AuthenticatedUser
from app.infrastructure.db.database import get_db

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get(
    "/logs",
    response_model=list[AuditLogResponse],
    status_code=status.HTTP_200_OK,
    summary="Consultar logs de auditoría (Admin)",
    description="Permite a los administradores inspeccionar el historial forense de eventos.",
)
async def list_audit_logs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=200),
    event_type: str | None = Query(default=None, description="Filtrar por tipo de evento"),
    user_id: uuid.UUID | None = Query(default=None, description="Filtrar por ID de usuario"),
    from_date: datetime | None = Query(default=None, description="Filtrar eventos desde esta fecha/hora"),
    to_date: datetime | None = Query(default=None, description="Filtrar eventos hasta esta fecha/hora"),
    current_user: AuthenticatedUser = Depends(require_audit_access),
    db: AsyncSession = Depends(get_db),
) -> Any:
    return await audit_service.get_audit_logs(
        db=db,
        skip=skip,
        limit=limit,
        event_type=event_type,
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
    )