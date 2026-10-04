"""Controlador HTTP REST para Auditoría de Hardening."""

import uuid
from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)

from app.auth.api import get_current_user
from app.core.rbac.context import AuthenticatedUser
from app.devices.api import DevicesAPI
from app.hardening.dependencies import (
    get_devices_api,
    get_hardening_service,
    require_hardening_permission,
)
from app.hardening.exceptions import InvalidExecutionPayloadException
from app.hardening.exporters import DOCXReportExporter, PDFReportExporter
from app.hardening.permissions import HardeningPermission
from app.hardening.schemas import (
    AuditExecutionRequest,
    AuditReportResponse,
    BackupAuditResponse,
    HardeningProfileResponse,
    RuleGroupResponse,
)
from app.hardening.service import HardeningService
from app.infrastructure.integrations.exceptions import (
    IntegrationConnectionError,
    IntegrationHTTPError,
)

router = APIRouter(prefix="/hardening", tags=["Hardening"])


# --- PERFILES ---

@router.get(
    "/profiles",
    response_model=List[HardeningProfileResponse],
    status_code=status.HTTP_200_OK,
)
async def list_profiles(
    standard_version: Optional[str] = Query(
        None, description="Filtrar por versión de estándar (ej. v1.0.0)"
    ),
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.READ)
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    return await service.list_profiles(standard_version=standard_version)


@router.get(
    "/profiles/{profile_id}",
    response_model=HardeningProfileResponse,
    status_code=status.HTTP_200_OK,
)
async def get_profile_by_id(
    profile_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.READ)
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    profile = await service.get_profile_by_id(profile_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil de hardening no encontrado.",
        )
    return profile


# --- AUDITORÍA EN VIVO ---

@router.post(
    "/audit",
    response_model=AuditReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def run_audit(
    payload: AuditExecutionRequest,
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.EXECUTE)
    ),
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
            standard_version=payload.standard_version,
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


# --- AUDITORÍA OFFLINE (ARCHIVO DE BACKUP) ---

@router.post(
    "/audit/backup",
    response_model=BackupAuditResponse,
    status_code=status.HTTP_200_OK,
)
async def audit_backup_file(
    file: UploadFile = File(..., description="Archivo de backup de FortiOS (.conf o .txt)"),
    profile_id: Optional[uuid.UUID] = Form(None, description="UUID del perfil a evaluar (opcional)"),
    standard_version: Optional[str] = Form(None, description="Versión estándar CIS (ej. v1.0.1)"),
    adhoc_rule_ids: List[str] = Form(default=[], description="Lista opcional de IDs de reglas para evaluación ad-hoc"),  # 👈 default=[]
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.EXECUTE)
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    """
    Pestaña de Auditoría Offline: recibe un archivo de backup .conf, lo analiza en memoria
    y retorna la evaluación y hallazgos sin requerir credenciales ni alterar la BD de dispositivos.
    Soporta evaluación por perfil completo o por lista ad-hoc de reglas.
    """
    raw_bytes = await file.read()
    file_content = raw_bytes.decode("utf-8", errors="ignore")

    if not file_content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo cargado está vacío.",
        )

    try:
        return await service.evaluate_backup_file(
            file_content=file_content,
            profile_id=profile_id,
            standard_version=standard_version,
            adhoc_rule_ids=adhoc_rule_ids,
        )
    except InvalidExecutionPayloadException as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error procesando el archivo de backup: {str(e)}",
        )


# --- REPORTES Y REGLAS ---

@router.get(
    "/reports",
    response_model=List[AuditReportResponse],
    status_code=status.HTTP_200_OK,
)
async def list_audit_reports(
    device_id: Optional[uuid.UUID] = Query(None, description="Filtrar por ID de dispositivo"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.READ)
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    return await service.list_reports(device_id=device_id, limit=limit, offset=offset)


@router.get(
    "/reports/{report_id}",
    response_model=AuditReportResponse,
    status_code=status.HTTP_200_OK,
)
async def get_audit_report_by_id(
    report_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.READ)
    ),
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
)
async def list_available_rules(
    standard: Optional[str] = Query(None, description="Filtrar por estándar (ej. CIS)"),
    standard_version: Optional[str] = Query(None, description="Filtrar por versión (ej. v1.0.0)"),
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.READ)
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    """Obtiene el catálogo maestro de reglas agrupadas para escaneos Ad-hoc desde la base de datos."""
    return await service.get_available_rules_catalog(
        standard=standard, standard_version=standard_version
    )


@router.get(
    "/reports/{report_id}/export",
    status_code=status.HTTP_200_OK,
)
async def export_audit_report(
    report_id: uuid.UUID,
    format: str = Query("pdf", pattern="^(pdf|docx)$", description="Formato del reporte (pdf o docx)"),
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.READ)
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    """Exporta un reporte de auditoría en formato PDF o DOCX."""
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
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )