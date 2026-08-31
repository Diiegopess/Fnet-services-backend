"""
Servicio de Autorización para VDOMs y Multi-Tenancy.
"""

import uuid
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI
from app.devices.vdoms.context import VDOMContext
from app.devices.vdoms.models import DeviceVDOM
from app.devices.vdoms.repository import VDOMRepository
from app.users.models import User


class VDOMAuthorizationService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.vdom_repo = VDOMRepository(db)
        self.clients_api = ClientsAPI(db)

    async def get_authorized_context(
        self, 
        vdom_id: uuid.UUID, 
        current_user: User
    ) -> VDOMContext | None:
        """
        Verifica si el usuario tiene acceso al VDOM:
        - Superusuarios y Admins globales tienen acceso irrestricto.
        - Técnicos requieren estar asignados al client_id del VDOM.
        """
        vdom: DeviceVDOM | None = await self.vdom_repo.get_by_id_with_device(vdom_id)
        if not vdom or not vdom.is_active:
            return None

        # 1. Superusuarios omiten validación de asignación
        if current_user.is_superuser:
            return self._build_context(vdom)

        # 2. Validar asignación del técnico con la fachada de clientes
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