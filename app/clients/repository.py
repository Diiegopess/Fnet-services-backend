"""
Módulo de Repositorio para el Dominio de Clientes.
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.clients.models import Client
from app.users.models import User


class ClientRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, client_id: uuid.UUID) -> Optional[Client]:
        """Obtiene un cliente por su UUID con los técnicos asignados cargados."""
        stmt = (
            select(Client)
            .options(selectinload(Client.assigned_technicians))
            .where(Client.id == client_id)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_name_or_tax_id(
        self,
        name: str,
        tax_id: Optional[str] = None,
        exclude_id: Optional[uuid.UUID] = None,
    ) -> Optional[Client]:
        """Verifica colisiones por nombre o identificación fiscal."""
        conditions = [Client.name == name]
        if tax_id:
            conditions.append(Client.tax_id == tax_id)

        stmt = select(Client).where(or_(*conditions))
        if exclude_id:
            stmt = stmt.where(Client.id != exclude_id)

        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def get_multi(
        self,
        skip: int = 0,
        limit: int = 50,
        is_active: Optional[bool] = None,
    ) -> Sequence[Client]:
        """Lista clientes con paginación y filtro opcional de estado."""
        stmt = (
            select(Client)
            .options(selectinload(Client.assigned_technicians))
            .offset(skip)
            .limit(limit)
            .order_by(Client.created_at.desc())
        )
        if is_active is not None:
            stmt = stmt.where(Client.is_active == is_active)

        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def create(self, client: Client) -> Client:
        """Persiste un nuevo cliente."""
        self.db.add(client)
        await self.db.commit()
        await self.db.refresh(client)
        return await self.get_by_id(client.id)  # Recarga con relaciones listas

    async def update(self, client: Client) -> Client:
        """Actualiza un cliente persistido."""
        self.db.add(client)
        await self.db.commit()
        await self.db.refresh(client)
        return await self.get_by_id(client.id)

    async def delete(self, client: Client) -> None:
        """Elimina un cliente de la base de datos."""
        await self.db.delete(client)
        await self.db.commit()

    async def get_users_by_ids(self, user_ids: list[uuid.UUID]) -> Sequence[User]:
        """Obtiene las entidades User para la asignación en client_technicians."""
        if not user_ids:
            return []
        stmt = select(User).where(User.id.in_(user_ids), User.is_active.is_(True))
        res = await self.db.execute(stmt)
        return res.scalars().all()