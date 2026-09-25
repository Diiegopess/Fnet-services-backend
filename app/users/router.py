"""
Módulo de Routers HTTP para el Dominio de Usuarios y RBAC.
"""

import uuid
from typing import Any
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.base import EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.core.rbac.context import AuthenticatedUser
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db
from app.users import service as user_service
from app.users.dependencies import get_current_user_entity, require_user_permission
from app.users.models import User
from app.users.permissions import UserPermission
from app.users.schemas import (
    RoleAssignSchema,
    RoleResponse,
    UserCreateAdmin,
    UserResponse,
    UserUpdate,
    UserUpdateAdmin,
)

router = APIRouter(prefix="/users", tags=["Users"])


def _build_metadata(request: Request, current_user: User) -> EventMetadata:
    return EventMetadata(
        actor_id=str(current_user.id),
        actor_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


# --- 1. REGISTRAR USUARIO CON PERMISOS ---
@router.post(
    "/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un usuario nuevo con roles",
)
async def admin_create_user(
    request: Request,
    user_in: UserCreateAdmin,
    current_user_auth: AuthenticatedUser = Depends(require_user_permission(UserPermission.CREATE)),
    current_user: User = Depends(get_current_user_entity),
    publisher: IEventPublisher = Depends(get_event_publisher),
    db: AsyncSession = Depends(get_db),
) -> Any:
    metadata = _build_metadata(request, current_user)
    return await user_service.admin_create_user(
        db=db,
        user_in=user_in,
        metadata=metadata,
        publisher=publisher,
    )


# --- 2. CONSULTAR MI PROPIO PERFIL ---
@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Obtener perfil actual",
)
async def read_current_user(
    current_user: User = Depends(get_current_user_entity),
) -> Any:
    return current_user


# --- 3. ACTUALIZAR MI PROPIO PERFIL ---
@router.patch("/me", response_model=UserResponse)
async def update_current_user(
    request: Request,
    user_in: UserUpdate,
    current_user: User = Depends(get_current_user_entity),
    publisher: IEventPublisher = Depends(get_event_publisher),
    db: AsyncSession = Depends(get_db),
) -> Any:
    metadata = EventMetadata(
        actor_id=str(current_user.id),
        actor_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return await user_service.update_user(
        db=db, user_id=current_user.id, user_in=user_in, metadata=metadata, publisher=publisher
    )


# --- 4. LISTAR USUARIOS ---
@router.get(
    "/",
    response_model=list[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="Listar usuarios",
)
async def list_users(
    skip: int = 0,
    limit: int = 50,
    current_user: AuthenticatedUser = Depends(require_user_permission(UserPermission.READ)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    return await user_service.get_multi(db=db, skip=skip, limit=limit)


# --- 5. ACTUALIZAR USUARIO ---
@router.patch("/{user_id}", response_model=UserResponse)
async def admin_update_user(
    request: Request,
    user_id: uuid.UUID,
    user_in: UserUpdateAdmin,
    current_user_auth: AuthenticatedUser = Depends(require_user_permission(UserPermission.UPDATE)),
    current_user: User = Depends(get_current_user_entity),
    publisher: IEventPublisher = Depends(get_event_publisher),
    db: AsyncSession = Depends(get_db),
) -> Any:
    metadata = EventMetadata(
        actor_id=str(current_user.id),
        actor_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return await user_service.update_user(
        db=db, user_id=user_id, user_in=user_in, metadata=metadata, publisher=publisher
    )


# --- 6. ASIGNAR ROLES A USUARIO ---
@router.post("/{user_id}/roles", response_model=UserResponse)
async def assign_user_roles(
    request: Request,
    user_id: uuid.UUID,
    payload: RoleAssignSchema,
    current_user_auth: AuthenticatedUser = Depends(require_user_permission(UserPermission.ASSIGN_ROLE)),
    current_user: User = Depends(get_current_user_entity),
    publisher: IEventPublisher = Depends(get_event_publisher),
    db: AsyncSession = Depends(get_db),
) -> Any:
    metadata = EventMetadata(
        actor_id=str(current_user.id),
        actor_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return await user_service.assign_roles_to_user(
        db=db, user_id=user_id, role_names=payload.role_names, metadata=metadata, publisher=publisher
    )


# --- 7. LISTAR CATÁLOGO DE ROLES ---
@router.get(
    "/roles/catalog",
    response_model=list[RoleResponse],
    status_code=status.HTTP_200_OK,
    summary="Listar catálogo de roles y permisos",
)
async def list_roles_catalog(
    current_user: AuthenticatedUser = Depends(require_user_permission(UserPermission.READ)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    return await user_service.list_roles(db=db)