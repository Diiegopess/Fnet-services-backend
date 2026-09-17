# app/services/hardening/router.py

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth.api import require_permission, get_current_user
from app.core.rbac.context import AuthenticatedUser
from app.devices.api import DevicesAPI
from app.infrastructure.integrations.exceptions import (
    IntegrationConnectionError,
    IntegrationHTTPError,
)
from app.infrastructure.integrations.fortinet.fetcher import FortinetConfigFetcher
from app.services.hardening.dependencies import (
    get_devices_api,
    get_hardening_service,
)
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
async def list_profiles(
    fortios_version: Optional[str] = Query(
        None, description="Filtrar por versión de FortiOS"
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    """Obtiene la lista de perfiles de evaluación disponibles."""
    return await service.list_profiles(standard_version=fortios_version)


@router.get(
    "/profiles/{profile_id}",
    response_model=HardeningProfileResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("hardening:read"))],
)
async def get_profile_by_id(
    profile_id: uuid.UUID,
    service: HardeningService = Depends(get_hardening_service),
):
    """Obtiene el detalle de un perfil de evaluación específico."""
    profile = await service.get_profile_by_id(profile_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil de hardening no encontrado.",
        )
    return profile


@router.post(
    "/audit",
    response_model=AuditReportResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("hardening:execute"))],
)
async def run_audit(
    payload: AuditExecutionRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: HardeningService = Depends(get_hardening_service),
    devices_api: DevicesAPI = Depends(get_devices_api),
):
    """Ejecuta una auditoría de hardening obteniendo la configuración en vivo del FortiGate."""
    raw_config = getattr(payload, "raw_config", None)

    # Si el frontend no envía el CLI dump en el body, se descarga directo del equipo
    if not raw_config or not raw_config.strip():
        conn = await devices_api.get_connection_data(
            device_id=payload.device_id
        )
        if not conn:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No se encontraron los datos de conexión para el dispositivo especificado.",
            )

        try:
            fetcher = FortinetConfigFetcher(timeout_seconds=30.0)
            vdom_name = getattr(conn, "vdom_name", None)

            raw_config = await fetcher.fetch_cli_dump(
                host=conn.host,
                port=conn.port,
                api_token=conn.decrypted_token,
                vdom=vdom_name,
            )
        except (IntegrationHTTPError, IntegrationConnectionError) as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Error al obtener la configuración desde el FortiGate: {str(e)}",
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error inesperado durante la extracción de configuración: {str(e)}",
            )

    # Extraer el ID del usuario directamente desde el token JWT
    user_id = getattr(current_user, "id", None)

    # Evaluación en el motor de Hardening
    report = await service.execute_audit(
        device_id=payload.device_id,
        raw_config=raw_config,
        execution_type=payload.execution_type,
        profile_id=payload.profile_id,
        adhoc_rule_ids=getattr(payload, "adhoc_rule_ids", None),
        vdom_id=getattr(payload, "vdom_id", None),
        executed_by=user_id,
    )
    return report

@router.get(
    "/reports",
    response_model=List[AuditReportResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("hardening:read"))],
)
async def list_audit_reports(
    device_id: Optional[uuid.UUID] = Query(None, description="Filtrar por ID de dispositivo"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    service: HardeningService = Depends(get_hardening_service),
):
    """Obtiene la lista/historial de reportes de auditoría guardados."""
    # Nota: Asegúrate de que tu HardeningService tenga el método list_reports o equivalente
    return await service.list_reports(device_id=device_id, limit=limit, offset=offset)


@router.get(
    "/reports/{report_id}",
    response_model=AuditReportResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("hardening:read"))],
)
async def get_audit_report_by_id(
    report_id: uuid.UUID,
    service: HardeningService = Depends(get_hardening_service),
):
    """Obtiene el detalle completo de un reporte de auditoría por su ID."""
    report = await service.get_report_by_id(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reporte de auditoría no encontrado.",
        )
    return report