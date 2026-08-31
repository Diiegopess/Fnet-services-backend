"""
Fachada Pública del Módulo de Clientes.
"""

import uuid
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.clients.models import Client


class ClientsAPI:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def is_client_active(self, client_id: uuid.UUID) -> bool:
        stmt = select(Client.is_active).where(Client.id == client_id)
        res = await self.db.execute(stmt)
        val = res.scalar_one_or_none()
        return bool(val)

    async def is_technician_assigned(self, client_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Verifica si un usuario específico está asignado al cliente."""
        stmt = (
            select(Client)
            .options(selectinload(Client.assigned_technicians))
            .where(Client.id == client_id, Client.is_active.is_(True))
        )
        res = await self.db.execute(stmt)
        client = res.scalar_one_or_none()
        if not client:
            return False
        return any(tech.id == user_id for tech in client.assigned_technicians)

    async def get_client_ids_for_technician(self, user_id: uuid.UUID) -> list[uuid.UUID]:
        """Retorna todos los IDs de clientes asignados a un técnico."""
        stmt = (
            select(Client.id)
            .join(Client.assigned_technicians)
            .where(Client.is_active.is_(True), Client.assigned_technicians.any(id=user_id))
        )
        res = await self.db.execute(stmt)
        return list(res.scalars().all())