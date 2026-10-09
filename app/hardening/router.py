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
    get_vdoms_api,
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
from app.vdoms.api import VDOMsAPI

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
    vdoms_api: VDOMsAPI = Depends(get_vdoms_api),
):
    """
    Ejecuta una auditoría de hardening.
    La unidad objetivo es la VDOM. Si no se envía vdom_id pero sí device_id,
    se evalúa automáticamente la VDOM 'root'.
    """
    raw_config = getattr(payload, "raw_config", None)
    connection_data = None
    target_device_id = payload.device_id
    target_vdom_id = payload.vdom_id
    vdom_name = "root"

    # Si no es evaluación offline por texto, resolvemos la conectividad en vivo
    if not raw_config:
        # Caso A: El usuario seleccionó directamente una VDOM (camino estándar)
        if target_vdom_id:
            vdom_dto = await vdoms_api.get_vdom_by_id(target_vdom_id)
            if not vdom_dto:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No se encontró la partición VDOM con ID '{target_vdom_id}'.",
                )
            # Si también mandó device_id, validamos consistencia
            if target_device_id and vdom_dto.device_id != target_device_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La VDOM indicada no pertenece al dispositivo proporcionado.",
                )
            target_device_id = vdom_dto.device_id
            vdom_name = vdom_dto.name

        # Caso B: El usuario solo envió device_id (equipo standalone o chasis completo)
        elif target_device_id:
            root_vdom = await vdoms_api.ensure_root_vdom(device_id=target_device_id)
            target_vdom_id = root_vdom.id
            vdom_name = root_vdom.name

        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Se requiere al menos 'vdom_id' o 'device_id' para una auditoría en vivo.",
            )

        # 1. Obtener conectividad y token del chasis físico
        conn = await devices_api.get_connection_data(device_id=target_device_id)
        if not conn:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No se encontraron los datos de conexión para el dispositivo asociado.",
            )

        # 2. Configurar el contexto de ejecución
        connection_data = {
            "host": conn.host,
            "port": conn.port,
            "token": conn.decrypted_token,
            "vdom": vdom_name,
            "has_vdom_enabled": getattr(conn, "has_vdom_enabled", False),
        }

    user_id = getattr(current_user, "id", None)

    try:
        report = await service.execute_audit(
            device_id=target_device_id,
            vdom_id=target_vdom_id,
            execution_type=payload.execution_type,
            connection_data=connection_data,
            raw_config=raw_config,
            profile_id=payload.profile_id,
            adhoc_rule_ids=getattr(payload, "adhoc_rule_ids", None),
            standard_version=payload.standard_version,
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
    adhoc_rule_ids: List[str] = Form(default=[], description="Lista opcional de IDs de reglas para evaluación ad-hoc"),
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.EXECUTE)
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    """
    Pestaña de Auditoría Offline: analiza un archivo de backup .conf en memoria
    sin persistir credenciales ni alterar el inventario de dispositivos.
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
    vdom_id: Optional[uuid.UUID] = Query(None, description="Filtrar por ID de VDOM"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: AuthenticatedUser = Depends(
        require_hardening_permission(HardeningPermission.READ)
    ),
    service: HardeningService = Depends(get_hardening_service),
):
    return await service.list_reports(
        device_id=device_id, vdom_id=vdom_id, limit=limit, offset=offset
    )


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