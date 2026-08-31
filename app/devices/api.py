"""
Fachada Pública del Módulo de Dispositivos.
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret
from app.devices.repository import DeviceRepository
from app.devices.vdoms.authorization import VDOMAuthorizationService
from app.devices.vdoms.context import VDOMContext
from app.devices.vdoms.repository import VDOMRepository
from app.users.models import User


class DevicesAPI:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.device_repo = DeviceRepository(db)
        self.vdom_repo = VDOMRepository(db)
        self.auth_service = VDOMAuthorizationService(db)

    async def get_vdom_context_for_user(self, vdom_id: uuid.UUID, user: User) -> Optional[VDOMContext]:
        """Obtiene el contexto validado de un VDOM para ejecutar operaciones seguras."""
        return await self.auth_service.get_authorized_context(vdom_id=vdom_id, current_user=user)

    async def get_decrypted_token_for_device(self, device_id: uuid.UUID) -> Optional[str]:
        """Recupera y descifra el API token del dispositivo para conexión de red."""
        device = await self.device_repo.get_by_id(device_id)
        if not device or not device.encrypted_api_token:
            return None
        return decrypt_secret(device.encrypted_api_token)

    async def list_vdoms_for_clients(self, client_ids: list[uuid.UUID]) -> Sequence[VDOMContext]:
        """Lista todos los VDOMs accesibles para una lista de clientes autorizados."""
        vdoms = await self.vdom_repo.list_by_client_ids(client_ids)
        return [
            VDOMContext(
                vdom_id=v.id,
                vdom_name=v.name,
                is_root=v.is_root,
                device_id=v.device.id,
                device_name=v.device.name,
                device_host=v.device.host,
                device_port=v.device.port,
                client_id=v.client_id,
            )
            for v in vdoms
        ]