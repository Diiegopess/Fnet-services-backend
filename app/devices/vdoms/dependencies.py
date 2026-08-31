"""
Dependencias para el Subdominio de VDOMs.
"""

import uuid
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.interfaces import IEventPublisher
from app.devices.exceptions import VDOMAccessDeniedError
from app.devices.vdoms.authorization import VDOMAuthorizationService
from app.devices.vdoms.context import VDOMContext
from app.devices.vdoms.service import VDOMService
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db
from app.users.dependencies import get_current_user
from app.users.models import User


def get_vdom_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
) -> VDOMService:
    return VDOMService(db=db, publisher=publisher)


async def get_authorized_vdom_context(
    vdom_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> VDOMContext:
    """
    Resuelve el VDOMContext validando que el usuario autenticado
    tenga acceso al cliente propietario del VDOM.
    """
    auth_service = VDOMAuthorizationService(db)
    context = await auth_service.get_authorized_context(vdom_id=vdom_id, current_user=current_user)
    if not context:
        raise VDOMAccessDeniedError()
    return context