from typing import List
from fastapi import APIRouter, Depends, status

from app.auth.api import require_permission
from app.services.hardening.dependencies import get_hardening_service
from app.services.hardening.schemas import (
    AuditExecutionRequest,
    AuditReportResponse,
    HardeningProfileResponse,
)
from app.services.hardening.service import HardeningService

router = APIRouter(prefix="/hardening", tags=["Hardening"])


@router.get(
    "/profiles",
    response_model=List[HardeningProfileResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("hardening:read"))],
)
async def get_profiles(
    service: HardeningService = Depends(get_hardening_service),
):
    """Obtiene el listado de perfiles de hardening activos con sus reglas asociadas."""
    return await service.list_profiles()


@router.post(
    "/audit",
    response_model=AuditReportResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("hardening:execute"))],
)
async def run_audit(
    payload: AuditExecutionRequest,
    service: HardeningService = Depends(get_hardening_service),
):
    """Ejecuta una auditoría de hardening."""
    report = await service.execute_audit(
        device_id=payload.device_id,
        raw_config=payload.raw_config,
        execution_type=payload.execution_type,
        profile_id=payload.profile_id,
        adhoc_rule_ids=payload.adhoc_rule_ids,
        vdom_id=payload.vdom_id,
    )
    return report