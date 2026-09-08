"""
Repositorio de Persistencia para VDOMs.
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.vdoms.models import DeviceVDOM


class VDOMRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, vdom_id: uuid.UUID) -> Optional[DeviceVDOM]:
        """Obtiene un VDOM por su ID primario."""
        stmt = select(DeviceVDOM).where(DeviceVDOM.id == vdom_id)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_device_and_name(self, device_id: uuid.UUID, name: str) -> Optional[DeviceVDOM]:
        """Obtiene un VDOM específico por ID de dispositivo y nombre del VDOM."""
        stmt = select(DeviceVDOM).where(
            DeviceVDOM.device_id == device_id,
            DeviceVDOM.name == name
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_device(self, device_id: uuid.UUID) -> Sequence[DeviceVDOM]:
        """Lista todos los VDOMs asociados a un dispositivo físico."""
        stmt = select(DeviceVDOM).where(DeviceVDOM.device_id == device_id)
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def list_by_client_ids(self, client_ids: list[uuid.UUID]) -> Sequence[DeviceVDOM]:
        """Lista los VDOMs activos asociados a una lista de IDs de clientes."""
        if not client_ids:
            return []
        stmt = select(DeviceVDOM).where(
            DeviceVDOM.client_id.in_(client_ids), 
            DeviceVDOM.is_active.is_(True)
        )
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def create(self, vdom: DeviceVDOM) -> DeviceVDOM:
        """Persiste un nuevo VDOM en la base de datos."""
        self.db.add(vdom)
        await self.db.commit()
        await self.db.refresh(vdom)
        return vdom

    async def update(self, vdom: DeviceVDOM) -> DeviceVDOM:
        """Guarda los cambios de un VDOM existente."""
        await self.db.commit()
        await self.db.refresh(vdom)
        return vdom

    async def delete(self, vdom: DeviceVDOM) -> None:
        """Elimina un VDOM de la base de datos."""
        await self.db.delete(vdom)
        await self.db.commit()