"""
Fachada Pública del Módulo de Dispositivos (Inter-Mapeo entre Subdominios).
"""

import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret
from app.devices.repository import DeviceRepository
from app.devices.schemas import DeviceConnectionData, DeviceResponse


class DevicesAPI:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.device_repo = DeviceRepository(db)

    async def get_device_by_id(self, device_id: uuid.UUID) -> Optional[DeviceResponse]:
        """Obtiene un dispositivo por su ID expuesto como DTO."""
        device = await self.device_repo.get_by_id(device_id)
        if not device:
            return None
        return DeviceResponse.model_validate(device)

    async def get_connection_data(self, device_id: uuid.UUID) -> Optional[DeviceConnectionData]:
        """
        Recupera los datos de red y credenciales descifradas necesarias 
        para conectores remotos (p. ej. sincronización desde VDOMs).
        """
        device = await self.device_repo.get_by_id(device_id)
        if not device or not device.encrypted_api_token:
            return None

        token_decrypted = decrypt_secret(device.encrypted_api_token)
        return DeviceConnectionData(
            device_id=device.id,
            host=device.host,
            port=device.port,
            decrypted_token=token_decrypted,
        )