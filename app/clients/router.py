"""
Controlador HTTP para el Dominio de Clientes.
"""

import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, status

from app.auth.api import RequirePermissions
from app.clients.dependencies import get_client_service
from app.clients.schemas import (
    ClientCreate,
    ClientResponse,
    ClientUpdate,
    TechnicianAssignmentSchema,
)
from app.clients.service import ClientService
from app.core.events.base import EventMetadata
from app.core.rbac.context import AuthenticatedUser
from app.core.rbac.permissions import PermissionEnum

router = APIRouter(prefix="/clients", tags=["Clients"])


def _extract_metadata(request: Request, user: AuthenticatedUser) -> EventMetadata:
    return EventMetadata(
        actor_id=str(user.id),
        actor_email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.post(
    "",
    response_model=ClientResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar un nuevo cliente u organización",
)
async def create_client(
    payload: ClientCreate,
    request: Request,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.CLIENTS_CREATE)),
    service: ClientService = Depends(get_client_service),
):
    metadata = _extract_metadata(request, current_user)
    return await service.create_client(data=payload, metadata=metadata)


@router.get(
    "",
    response_model=list[ClientResponse],
    summary="Listar clientes con paginación",
)
async def list_clients(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    is_active: Optional[bool] = Query(None),
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.CLIENTS_READ)),
    service: ClientService = Depends(get_client_service),
):
    return await service.get_multi(skip=skip, limit=limit, is_active=is_active)


@router.get(
    "/{client_id}",
    response_model=ClientResponse,
    summary="Obtener detalle de un cliente por ID",
)
async def get_client(
    client_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.CLIENTS_READ)),
    service: ClientService = Depends(get_client_service),
):
    return await service.get_by_id_or_fail(client_id)


@router.patch(
    "/{client_id}",
    response_model=ClientResponse,
    summary="Actualizar información de un cliente",
)
async def update_client(
    client_id: uuid.UUID,
    payload: ClientUpdate,
    request: Request,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.CLIENTS_UPDATE)),
    service: ClientService = Depends(get_client_service),
):
    metadata = _extract_metadata(request, current_user)
    return await service.update_client(client_id=client_id, data=payload, metadata=metadata)


@router.post(
    "/{client_id}/technicians",
    response_model=ClientResponse,
    summary="Asignar técnicos/usuarios a un cliente",
)
async def assign_technicians(
    client_id: uuid.UUID,
    payload: TechnicianAssignmentSchema,
    request: Request,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.CLIENTS_ASSIGN_TECHNICIAN)),
    service: ClientService = Depends(get_client_service),
):
    metadata = _extract_metadata(request, current_user)
    return await service.assign_technicians(
        client_id=client_id,
        technician_ids=payload.technician_ids,
        metadata=metadata,
    )


@router.delete(
    "/{client_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un cliente",
)
async def delete_client(
    client_id: uuid.UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.CLIENTS_DELETE)),
    service: ClientService = Depends(get_client_service),
):
    metadata = _extract_metadata(request, current_user)
    await service.delete_client(client_id=client_id, metadata=metadata)