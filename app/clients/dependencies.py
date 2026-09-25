"""
Módulo de Dependencias para el Dominio de Clientes.
"""

from typing import Callable
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api import require_permission
from app.clients.permissions import ClientPermission
from app.clients.service import ClientService
from app.core.events.interfaces import IEventPublisher
from app.core.rbac.context import AuthenticatedUser
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db


def get_client_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
) -> ClientService:
    return ClientService(db=db, publisher=publisher)


def require_client_permission(permission: ClientPermission) -> Callable[..., AuthenticatedUser]:
    """Inyecta la validación del permiso específico dentro del dominio de clientes."""
    return require_permission(permission.value)