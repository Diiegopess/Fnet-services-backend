"""
Repositorio de Persistencia para Dispositivos Físicos (Chasis).
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.devices.models import FortigateDevice


class DeviceRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, device_id: uuid.UUID) -> Optional[FortigateDevice]:
        stmt = (
            select(FortigateDevice)
            .options(selectinload(FortigateDevice.vdoms))
            .where(FortigateDevice.id == device_id)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_host(self, host: str) -> Optional[FortigateDevice]:
        stmt = select(FortigateDevice).where(FortigateDevice.host == host)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_multi(self, skip: int = 0, limit: int = 50) -> Sequence[FortigateDevice]:
        stmt = (
            select(FortigateDevice)
            .options(selectinload(FortigateDevice.vdoms))
            .offset(skip)
            .limit(limit)
            .order_by(FortigateDevice.created_at.desc())
        )
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def create(self, device: FortigateDevice) -> FortigateDevice:
        self.db.add(device)
        await self.db.commit()
        await self.db.refresh(device)
        return await self.get_by_id(device.id)

    async def update(self, device: FortigateDevice) -> FortigateDevice:
        self.db.add(device)
        await self.db.commit()
        await self.db.refresh(device)
        return await self.get_by_id(device.id)

    async def delete(self, device: FortigateDevice) -> None:
        await self.db.delete(device)
        await self.db.commit()