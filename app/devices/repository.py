"""
Repositorio de Persistencia para Dispositivos Físicos (Chasis).
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.devices.models import FortigateDevice
from app.vdoms.models import DeviceVDOM


class DeviceRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, device_id: uuid.UUID) -> Optional[FortigateDevice]:
        """Obtiene un dispositivo por su ID primario."""
        stmt = select(FortigateDevice).where(FortigateDevice.id == device_id)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_host(self, host: str) -> Optional[FortigateDevice]:
        """Obtiene un dispositivo por su IP o FQDN."""
        stmt = select(FortigateDevice).where(FortigateDevice.host == host)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_multi(
        self, 
        skip: int = 0, 
        limit: int = 50, 
        client_id: Optional[uuid.UUID] = None
    ) -> Sequence[FortigateDevice]:
        """
        Obtiene una lista paginada de dispositivos.
        Si se especifica client_id, filtra a través de las particiones VDOM asociadas.
        """
        if client_id is not None:
            # Consulta relacional a través de las particiones (VDOMs)
            stmt = (
                select(FortigateDevice)
                .join(DeviceVDOM, DeviceVDOM.device_id == FortigateDevice.id)
                .where(DeviceVDOM.client_id == client_id)
                .distinct()
            )
        else:
            stmt = select(FortigateDevice)

        stmt = (
            stmt
            .offset(skip)
            .limit(limit)
            .order_by(FortigateDevice.created_at.desc())
        )
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def create(self, device: FortigateDevice) -> FortigateDevice:
        """
        Persiste un nuevo dispositivo en la sesión.
        Usa flush() para asignar ID y mantener la transacción viva
        mientras se crea la VDOM 'root'.
        """
        self.db.add(device)
        await self.db.flush()
        await self.db.refresh(device)
        return device

    async def update(self, device: FortigateDevice) -> FortigateDevice:
        """Actualiza el estado de un dispositivo existente."""
        await self.db.flush()
        await self.db.refresh(device)
        return device

    async def delete(self, device: FortigateDevice) -> None:
        """Elimina un dispositivo de la base de datos."""
        await self.db.delete(device)
        await self.db.flush()