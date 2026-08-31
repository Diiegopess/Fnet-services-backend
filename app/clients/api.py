"""
API Pública del Módulo de Clientes.

Punto único de contacto interno para otros módulos del backend.
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.repository import ClientRepository
from app.clients.schemas import ClientResponse


class ClientsAPI:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = ClientRepository(db)

    async def get_client_by_id(self, client_id: uuid.UUID) -> Optional[ClientResponse]:
        """Obtiene el DTO del cliente por UUID."""
        client = await self.repo.get_by_id(client_id)
        return ClientResponse.model_validate(client) if client else None

    async def is_client_active(self, client_id: uuid.UUID) -> bool:
        """Verifica si el cliente existe y está activo."""
        client = await self.repo.get_by_id(client_id)
        return bool(client and client.is_active)

    async def is_technician_assigned(self, client_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Verifica si un usuario específico está asignado a un cliente."""
        client = await self.repo.get_by_id(client_id)
        if not client:
            return False
        return any(tech.id == user_id for tech in client.assigned_technicians)

    async def list_active_clients(self, skip: int = 0, limit: int = 100) -> Sequence[ClientResponse]:
        """Lista clientes activos para selects o validaciones intermodulares."""
        clients = await self.repo.get_multi(skip=skip, limit=limit, is_active=True)
        return [ClientResponse.model_validate(c) for c in clients]