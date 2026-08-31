"""
Repositorio de Persistencia para VDOMs.
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.devices.vdoms.models import DeviceVDOM


class VDOMRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, vdom_id: uuid.UUID) -> Optional[DeviceVDOM]:
        stmt = select(DeviceVDOM).where(DeviceVDOM.id == vdom_id)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_id_with_device(self, vdom_id: uuid.UUID) -> Optional[DeviceVDOM]:
        stmt = (
            select(DeviceVDOM)
            .options(selectinload(DeviceVDOM.device))
            .where(DeviceVDOM.id == vdom_id)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_device(self, device_id: uuid.UUID) -> Sequence[DeviceVDOM]:
        stmt = select(DeviceVDOM).where(DeviceVDOM.device_id == device_id)
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def list_by_client_ids(self, client_ids: list[uuid.UUID]) -> Sequence[DeviceVDOM]:
        if not client_ids:
            return []
        stmt = (
            select(DeviceVDOM)
            .options(selectinload(DeviceVDOM.device))
            .where(DeviceVDOM.client_id.in_(client_ids), DeviceVDOM.is_active.is_(True))
        )
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def create(self, vdom: DeviceVDOM) -> DeviceVDOM:
        self.db.add(vdom)
        await self.db.commit()
        await self.db.refresh(vdom)
        return vdom

    async def delete(self, vdom: DeviceVDOM) -> None:
        await self.db.delete(vdom)
        await self.db.commit()