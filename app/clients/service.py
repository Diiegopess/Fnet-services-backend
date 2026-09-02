"""
Módulo de Servicios para el Dominio de Clientes.
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.exceptions import (
    ClientAlreadyExistsError,
    ClientNotFoundError,
    InvalidTechnicianAssignmentError,
)
from app.clients.models import Client
from app.clients.repository import ClientRepository
from app.clients.schemas import ClientCreate, ClientUpdate
from app.core.config import settings
from app.core.events.base import DomainEvent, EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.users.api import UsersAPI


class ClientService:
    def __init__(self, db: AsyncSession, publisher: Optional[IEventPublisher] = None):
        self.db = db
        self.publisher = publisher
        self.repo = ClientRepository(db)
        self.users_api = UsersAPI(db)

    async def get_by_id_or_fail(self, client_id: uuid.UUID) -> Client:
        """Obtiene un cliente por ID o eleva excepción 404."""
        client = await self.repo.get_by_id(client_id)
        if not client:
            raise ClientNotFoundError()
        return client

    async def get_multi(
        self,
        skip: int = 0,
        limit: int = 50,
        is_active: Optional[bool] = None,
    ) -> Sequence[Client]:
        """Obtiene la lista paginada de clientes."""
        return await self.repo.get_multi(skip=skip, limit=limit, is_active=is_active)

    async def create_client(
        self,
        data: ClientCreate,
        metadata: Optional[EventMetadata] = None,
    ) -> Client:
        """Crea un nuevo cliente validando unicidad de nombre y NIT/RFC."""
        existing = await self.repo.get_by_name_or_tax_id(name=data.name, tax_id=data.tax_id)
        if existing:
            raise ClientAlreadyExistsError()

        client = Client(
            name=data.name,
            tax_id=data.tax_id,
            contact_email=data.contact_email,
            contact_phone=data.contact_phone,
            address=data.address,
            is_active=data.is_active,
        )
        created_client = await self.repo.create(client)

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="clients.client_created",
                metadata=metadata,
                payload={
                    "client_id": str(created_client.id),
                    "name": created_client.name,
                    "tax_id": created_client.tax_id,
                },
            )
            await self.publisher.publish(
                stream_or_topic=getattr(settings, "AUDIT_STREAM_NAME", settings.AUTH_STREAM_NAME),
                event=event,
            )

        return created_client

    async def update_client(
        self,
        client_id: uuid.UUID,
        data: ClientUpdate,
        metadata: Optional[EventMetadata] = None,
    ) -> Client:
        """Actualiza la información de un cliente existente."""
        client = await self.get_by_id_or_fail(client_id)

        update_data = data.model_dump(exclude_unset=True)
        if "name" in update_data or "tax_id" in update_data:
            name_check = update_data.get("name", client.name)
            tax_id_check = update_data.get("tax_id", client.tax_id)
            existing = await self.repo.get_by_name_or_tax_id(
                name=name_check, tax_id=tax_id_check, exclude_id=client.id
            )
            if existing:
                raise ClientAlreadyExistsError()

        for field, value in update_data.items():
            setattr(client, field, value)

        updated_client = await self.repo.update(client)

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="clients.client_updated",
                metadata=metadata,
                payload={
                    "client_id": str(updated_client.id),
                    "updated_fields": list(update_data.keys()),
                },
            )
            await self.publisher.publish(
                stream_or_topic=getattr(settings, "AUDIT_STREAM_NAME", settings.AUTH_STREAM_NAME),
                event=event,
            )

        return updated_client

    async def assign_technicians(
        self,
        client_id: uuid.UUID,
        technician_ids: list[uuid.UUID],
        metadata: Optional[EventMetadata] = None,
    ) -> Client:
        """Asocia técnicos activos a un cliente tras validar existencia mediante UsersAPI."""
        client = await self.get_by_id_or_fail(client_id)

        # Validación desacoplada usando la fachada de Users
        all_valid = await self.users_api.validate_active_users(technician_ids)
        if not all_valid:
            raise InvalidTechnicianAssignmentError(
                "Uno o más técnicos no existen, están inactivos o tienen identificadores inválidos."
            )

        # Persistencia en tabla asociativa
        await self.repo.set_assigned_technicians(client_id=client.id, technician_ids=technician_ids)
        updated_client = await self.get_by_id_or_fail(client_id)

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="clients.technicians_assigned",
                metadata=metadata,
                payload={
                    "client_id": str(client.id),
                    "technician_ids": [str(t_id) for t_id in technician_ids],
                },
            )
            await self.publisher.publish(
                stream_or_topic=getattr(settings, "AUDIT_STREAM_NAME", settings.AUTH_STREAM_NAME),
                event=event,
            )

        return updated_client

    async def delete_client(
        self,
        client_id: uuid.UUID,
        metadata: Optional[EventMetadata] = None,
    ) -> None:
        """Elimina un cliente del sistema."""
        client = await self.get_by_id_or_fail(client_id)
        await self.repo.delete(client)

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="clients.client_deleted",
                metadata=metadata,
                payload={"client_id": str(client_id), "name": client.name},
            )
            await self.publisher.publish(
                stream_or_topic=getattr(settings, "AUDIT_STREAM_NAME", settings.AUTH_STREAM_NAME),
                event=event,
            )