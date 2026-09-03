"""Controlador HTTP para VDOMs (Particiones Lógicas)."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth.api import RequirePermissions
from app.core.events.base import EventMetadata
from app.core.rbac.context import AuthenticatedUser
from app.core.rbac.permissions import PermissionEnum
from app.devices.exceptions import (
    DeviceConnectionError,
    DeviceNotFoundError,
)
from app.devices.vdoms.context import VDOMContext
from app.devices.vdoms.dependencies import (
    get_authorized_vdom_context,
    get_vdom_service,
)
from app.devices.vdoms.schemas import (
    VDOMCreate,
    VDOMResponse,
    VDOMSyncResult,
    VDOMUpdate,
)
from app.devices.vdoms.service import VDOMService

router = APIRouter(prefix="/vdoms", tags=["Device VDOMs"])


def _extract_metadata(request: Request, user: AuthenticatedUser) -> EventMetadata:
    return EventMetadata(
        actor_id=str(user.id),
        actor_email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


def _clean_exception_msg(exc: Exception) -> str:
    """Sanitiza mensajes de excepción para prevenir 'ascii codec' en FastAPI/Starlette."""
    text = str(exc)
    return text.encode("utf-8", errors="replace").decode("utf-8")


@router.post(
    "",
    response_model=VDOMResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar y asignar una partición VDOM a un cliente",
)
async def create_vdom(
    payload: VDOMCreate,
    request: Request,
    current_user: AuthenticatedUser = Depends(
        RequirePermissions(PermissionEnum.VDOMS_CREATE)
    ),
    service: VDOMService = Depends(get_vdom_service),
):
    metadata = _extract_metadata(request, current_user)
    return await service.create_vdom(data=payload, metadata=metadata)


@router.post(
    "/device/{device_id}/sync",
    response_model=VDOMSyncResult,
    summary="Sincronizar VDOMs detectados en el chasis físico FortiGate",
)
async def sync_vdoms(
    device_id: uuid.UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(
        RequirePermissions(PermissionEnum.VDOMS_CREATE)
    ),
    service: VDOMService = Depends(get_vdom_service),
):
    metadata = _extract_metadata(request, current_user)
    try:
        return await service.sync_device_vdoms(
            device_id=device_id, metadata=metadata
        )
    except DeviceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dispositivo {device_id} no encontrado.",
        )
    except DeviceConnectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_clean_exception_msg(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al sincronizar VDOMs: {_clean_exception_msg(exc)}",
        )


@router.get(
    "/device/{device_id}",
    response_model=list[VDOMResponse],
    summary="Listar todos los VDOMs de un dispositivo específico",
)
async def list_vdoms_by_device(
    device_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        RequirePermissions(PermissionEnum.VDOMS_READ)
    ),
    service: VDOMService = Depends(get_vdom_service),
):
    return await service.list_by_device(device_id)


@router.get(
    "/{vdom_id}",
    response_model=VDOMResponse,
    summary="Obtener detalle de un VDOM con validación de acceso multi-tenant",
)
async def get_vdom(
    vdom_id: uuid.UUID,
    context: VDOMContext = Depends(get_authorized_vdom_context),
    service: VDOMService = Depends(get_vdom_service),
):
    return await service.get_by_id_or_fail(vdom_id)


@router.patch(
    "/{vdom_id}",
    response_model=VDOMResponse,
    summary="Actualizar un VDOM o reasignar su cliente propietario",
)
async def update_vdom(
    vdom_id: uuid.UUID,
    payload: VDOMUpdate,
    request: Request,
    current_user: AuthenticatedUser = Depends(
        RequirePermissions(PermissionEnum.VDOMS_UPDATE)
    ),
    service: VDOMService = Depends(get_vdom_service),
):
    metadata = _extract_metadata(request, current_user)
    return await service.update_vdom(
        vdom_id=vdom_id, data=payload, metadata=metadata
    )


@router.delete(
    "/{vdom_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un VDOM",
)
async def delete_vdom(
    vdom_id: uuid.UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(
        RequirePermissions(PermissionEnum.VDOMS_DELETE)
    ),
    service: VDOMService = Depends(get_vdom_service),
):
    metadata = _extract_metadata(request, current_user)
    await service.delete_vdom(vdom_id=vdom_id, metadata=metadata)