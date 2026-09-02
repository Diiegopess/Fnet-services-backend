"""
Servicio de Autorización para VDOMs y Multi-Tenancy.
"""

import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI
from app.core.rbac.context import AuthenticatedUser
from app.devices.vdoms.context import VDOMContext
from app.devices.vdoms.models import DeviceVDOM
from app.devices.vdoms.repository import VDOMRepository


class VDOMAuthorizationService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.vdom_repo = VDOMRepository(db)
        self.clients_api = ClientsAPI(db)

    async def get_authorized_context(
        self, 
        vdom_id: uuid.UUID, 
        current_user: AuthenticatedUser
    ) -> VDOMContext | None:
        """
        Verifica si el usuario tiene acceso al VDOM:
        - Superusuarios tienen acceso irrestricto (incluso a VDOMs no asignados).
        - Técnicos requieren que el VDOM tenga un client_id y estar asignados a él.
        """
        vdom: DeviceVDOM | None = await self.vdom_repo.get_by_id_with_device(vdom_id)
        if not vdom or not vdom.is_active:
            return None

        # 1. Superusuarios omiten validación de asignación de cliente
        if current_user.is_superuser:
            return self._build_context(vdom)

        # 2. Si el VDOM no tiene cliente asignado, ningún técnico ordinario puede acceder
        if not vdom.client_id:
            return None

        # 3. Validar asignación del técnico mediante la fachada pública
        has_access = await self.clients_api.is_technician_assigned(
            client_id=vdom.client_id, 
            user_id=current_user.id
        )
        if not has_access:
            return None

        return self._build_context(vdom)

    @staticmethod
    def _build_context(vdom: DeviceVDOM) -> VDOMContext:
        return VDOMContext(
            vdom_id=vdom.id,
            vdom_name=vdom.name,
            is_root=vdom.is_root,
            device_id=vdom.device.id,
            device_name=vdom.device.name,
            device_host=vdom.device.host,
            device_port=vdom.device.port,
            client_id=vdom.client_id,
        )