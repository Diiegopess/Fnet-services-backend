"""
Dependencias para el Subdominio de VDOMs.
"""

import uuid
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api import RequirePermissions
from app.core.events.interfaces import IEventPublisher
from app.core.rbac.context import AuthenticatedUser
from app.core.rbac.permissions import PermissionEnum
from app.devices.exceptions import VDOMAccessDeniedError
from app.devices.vdoms.authorization import VDOMAuthorizationService
from app.devices.vdoms.context import VDOMContext
from app.devices.vdoms.service import VDOMService
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db


def get_vdom_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
) -> VDOMService:
    return VDOMService(db=db, publisher=publisher)


async def get_authorized_vdom_context(
    vdom_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(RequirePermissions(PermissionEnum.VDOMS_READ)),
) -> VDOMContext:
    """
    Resuelve el VDOMContext validando que el usuario autenticado
    tenga permisos de lectura y acceso al cliente propietario del VDOM.
    """
    auth_service = VDOMAuthorizationService(db)
    context = await auth_service.get_authorized_context(vdom_id=vdom_id, current_user=current_user)
    if not context:
        raise VDOMAccessDeniedError()
    return context