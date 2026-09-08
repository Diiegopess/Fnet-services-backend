"""
Dependencias de FastAPI e Inyección de Contexto Autorizado para VDOMs.
"""

import uuid
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI
from app.infrastructure.db.database import get_db
from app.core.events.interfaces import IEventPublisher
from app.infrastructure.brokers.factory import get_event_publisher
from app.core.rbac.context import AuthenticatedUser
from app.core.rbac.permissions import PermissionEnum
from app.auth.api import RequirePermissions

from app.vdoms.exceptions import VDOMAccessDeniedError, VDOMNotFoundError
from app.vdoms.repository import VDOMRepository
from app.vdoms.schemas import VDOMContext
from app.vdoms.service import VDOMService


def get_vdom_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
) -> VDOMService:
    """Inyecta la instancia del servicio de negocio de VDOMs."""
    return VDOMService(db=db, publisher=publisher)


async def get_authorized_vdom_context(
    vdom_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.VDOMS_READ)),
) -> VDOMContext:
    """
    Resuelve e inyecta el VDOMContext validado.
    
    Verifica que:
    1. El VDOM exista y esté activo.
    2. El usuario tenga acceso (Superusuarios acceden libremente; los técnicos
       requieren asignación explicita al cliente dueño del VDOM).
    """
    vdom_repo = VDOMRepository(db)
    vdom = await vdom_repo.get_by_id(vdom_id)

    if not vdom or not vdom.is_active:
        raise VDOMNotFoundError()

    # 1. Superusuarios omiten validación de cliente
    if current_user.is_superuser:
        return VDOMContext(
            vdom_id=vdom.id,
            vdom_name=vdom.name,
            is_root=vdom.is_root,
            device_id=vdom.device_id,
            client_id=vdom.client_id,
        )

    # 2. Un VDOM sin cliente no es accesible por un técnico estándar
    if not vdom.client_id:
        raise VDOMAccessDeniedError(detail="El VDOM no tiene un cliente asignado.")

    # 3. Validar si el técnico está asignado al cliente del VDOM
    clients_api = ClientsAPI(db)
    has_access = await clients_api.is_technician_assigned(
        client_id=vdom.client_id,
        user_id=current_user.id
    )

    if not has_access:
        raise VDOMAccessDeniedError()

    return VDOMContext(
        vdom_id=vdom.id,
        vdom_name=vdom.name,
        is_root=vdom.is_root,
        device_id=vdom.device_id,
        client_id=vdom.client_id,
    )