"""
Controlador HTTP REST para Chasis Físicos FortiGate.
"""

import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, status

from app.auth.api import RequirePermissions
from app.core.events.base import EventMetadata
from app.core.rbac.context import AuthenticatedUser
from app.core.rbac.permissions import PermissionEnum
from app.devices.dependencies import get_device_service
from app.devices.schemas import (
    ConnectivityCheckResult,
    DeviceCreate,
    DeviceResponse,
    DeviceTestConnectionRequest,
    DeviceUpdate,
)
from app.devices.service import DeviceService

router = APIRouter(prefix="/devices", tags=["Devices"])


def _extract_metadata(request: Request, user: AuthenticatedUser) -> EventMetadata:
    return EventMetadata(
        actor_id=str(user.id),
        actor_email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.get(
    "/supported-versions",
    response_model=list[dict[str, str]],
    summary="Obtener versiones de FortiOS soportadas",
)
async def get_supported_fortios_versions():
    return [
        {"label": "FortiOS v7.4.x", "value": "7.4"},
        {"label": "FortiOS v7.2.x (Recomendado)", "value": "7.2"},
        {"label": "FortiOS v7.0.x", "value": "7.0"},
        {"label": "FortiOS v6.4.x", "value": "6.4"},
        {"label": "Entorno Mock / Pruebas", "value": "mock"},
    ]


@router.post(
    "/test-connection",
    response_model=ConnectivityCheckResult,
    summary="Probar conectividad y credenciales contra un FortiGate sin persistirlo",
)
async def test_device_connection(
    payload: DeviceTestConnectionRequest,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.DEVICES_TEST_CONNECTION)),
    service: DeviceService = Depends(get_device_service),
):
    return await service.test_connectivity(
        host=payload.host,
        port=payload.port,
        api_token=payload.api_token,
    )


@router.post(
    "/{device_id}/test-connection",
    response_model=ConnectivityCheckResult,
    summary="Probar conectividad de un dispositivo ya registrado",
)
async def test_existing_device_connection(
    device_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.DEVICES_TEST_CONNECTION)),
    service: DeviceService = Depends(get_device_service),
):
    return await service.test_existing_device_connectivity(device_id)


@router.get(
    "",
    response_model=list[DeviceResponse],
    summary="Listar dispositivos físicos registrados (Filtrable por cliente)",
)
async def list_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    client_id: Optional[uuid.UUID] = Query(None, description="Filtrar por ID de cliente"),
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.DEVICES_READ)),
    service: DeviceService = Depends(get_device_service),
):
    return await service.get_multi(skip=skip, limit=limit, client_id=client_id)


@router.post(
    "",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar un nuevo chasis FortiGate",
)
async def create_device(
    payload: DeviceCreate,
    request: Request,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.DEVICES_CREATE)),
    service: DeviceService = Depends(get_device_service),
):
    metadata = _extract_metadata(request, current_user)
    return await service.create_device(data=payload, metadata=metadata)


@router.get(
    "/{device_id}",
    response_model=DeviceResponse,
    summary="Obtener detalle de un dispositivo por ID",
)
async def get_device(
    device_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.DEVICES_READ)),
    service: DeviceService = Depends(get_device_service),
):
    return await service.get_by_id_or_fail(device_id)


@router.patch(
    "/{device_id}",
    response_model=DeviceResponse,
    summary="Actualizar parámetros de conexión de un dispositivo",
)
async def update_device(
    device_id: uuid.UUID,
    payload: DeviceUpdate,
    request: Request,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.DEVICES_UPDATE)),
    service: DeviceService = Depends(get_device_service),
):
    metadata = _extract_metadata(request, current_user)
    return await service.update_device(device_id=device_id, data=payload, metadata=metadata)


@router.delete(
    "/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un dispositivo registrado",
)
async def delete_device(
    device_id: uuid.UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.DEVICES_DELETE)),
    service: DeviceService = Depends(get_device_service),
):
    metadata = _extract_metadata(request, current_user)
    await service.delete_device(device_id=device_id, metadata=metadata)