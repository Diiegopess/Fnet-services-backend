# app/services/hardening/router.py

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from app.services.hardening.exporters import DOCXReportExporter, PDFReportExporter

from app.auth.api import require_permission, get_current_user
from app.core.rbac.context import AuthenticatedUser
from app.devices.api import DevicesAPI
from app.infrastructure.integrations.exceptions import (
    IntegrationConnectionError,
    IntegrationHTTPError,
)
from app.services.hardening.dependencies import (
    get_devices_api,
    get_hardening_service,
)
from app.services.hardening.exceptions import InvalidExecutionPayloadException
from app.services.hardening.schemas import (
    AuditExecutionRequest,
    AuditReportResponse,
    HardeningProfileResponse,
    RuleGroupResponse,
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
    standard_version: Optional[str] = Query(
        None, description="Filtrar por versión de estándar (ej. v1.0.0)"
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    return await service.list_profiles(standard_version=standard_version)


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
    """Ejecuta una auditoría de hardening declarativa aislando los endpoints requeridos."""
    raw_config = getattr(payload, "raw_config", None)
    connection_data = None

    if not raw_config:
        conn = await devices_api.get_connection_data(device_id=payload.device_id)
        if not conn:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No se encontraron los datos de conexión para el dispositivo especificado.",
            )

        connection_data = {
            "host": conn.host,
            "port": conn.port,
            "token": conn.decrypted_token,
            "vdom": getattr(conn, "vdom_name", None),
        }

    user_id = getattr(current_user, "id", None)

    try:
        report = await service.execute_audit(
            device_id=payload.device_id,
            execution_type=payload.execution_type,
            connection_data=connection_data,
            raw_config=raw_config,
            profile_id=payload.profile_id,
            adhoc_rule_ids=getattr(payload, "adhoc_rule_ids", None),
            standard_version=payload.standard_version,  # <-- Pasa la versión declarada al servicio
            vdom_id=getattr(payload, "vdom_id", None),
            executed_by=user_id,
        )
        return report

    except (IntegrationHTTPError, IntegrationConnectionError) as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Error de comunicación con el dispositivo FortiGate: {str(e)}",
        )
    except InvalidExecutionPayloadException as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error durante la ejecución del proceso de auditoría: {str(e)}",
        )


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
    report = await service.get_report_by_id(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reporte de auditoría no encontrado.",
        )
    return report

@router.get(
    "/rules",
    response_model=List[RuleGroupResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("hardening:read"))],
)
async def list_available_rules(
    standard: Optional[str] = Query(None, description="Filtrar por estándar (ej. CIS)"),
    standard_version: Optional[str] = Query(None, description="Filtrar por versión (ej. v1.0.0)"),
    service: HardeningService = Depends(get_hardening_service),
):
    """Obtiene el catálogo maestro de reglas agrupadas para escaneos Ad-hoc desde la base de datos."""
    return await service.get_available_rules_catalog(standard=standard, standard_version=standard_version)


@router.get(
    "/reports/{report_id}/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("hardening:read"))],
)
async def export_audit_report(
    report_id: uuid.UUID,
    format: str = Query("pdf", pattern="^(pdf|docx)$", description="Formato del reporte (pdf o docx)"),
    service: HardeningService = Depends(get_hardening_service),
):
    """
    Exporta un reporte de auditoría en formato PDF o DOCX.
    """
    report = await service.get_report_by_id(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reporte de auditoría no encontrado.",
        )

    if format == "pdf":
        exporter = PDFReportExporter()
        media_type = "application/pdf"
        filename = f"reporte_hardening_{report_id}.pdf"
    else:
        exporter = DOCXReportExporter()
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        filename = f"reporte_hardening_{report_id}.docx"

    file_bytes = exporter.export(report)

    return Response(
        content=file_bytes,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )