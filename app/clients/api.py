"""
Fachada Pública del Módulo de Clientes.
"""

import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.exceptions import ClientNotFoundError
from app.clients.repository import ClientRepository

__all__ = ["ClientsAPI", "ClientNotFoundError"]


class ClientsAPI:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = ClientRepository(db)

    async def is_client_active(self, client_id: uuid.UUID) -> bool:
        """Verifica si el cliente existe y está activo."""
        client = await self.repo.get_by_id(client_id)
        return bool(client and client.is_active)

    async def validate_client_is_active(self, client_id: uuid.UUID) -> None:
        """Valida que el cliente exista y esté activo; de lo contrario lanza ClientNotFoundError."""
        if not await self.is_client_active(client_id):
            raise ClientNotFoundError("El cliente asociado no existe o está inactivo.")

    async def is_technician_assigned(self, client_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Verifica si un usuario específico está asignado al cliente."""
        client = await self.repo.get_by_id(client_id)
        if not client or not client.is_active:
            return False
        return any(tech.id == user_id for tech in client.assigned_technicians)

    async def get_client_ids_for_technician(self, user_id: uuid.UUID) -> list[uuid.UUID]:
        """Retorna todos los IDs de clientes activos asignados a un técnico."""
        return await self.repo.get_client_ids_by_technician(user_id)