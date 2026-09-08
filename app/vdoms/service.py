"""
Servicio de Negocio para el Módulo de VDOMs.
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI
from app.core.config import settings
from app.core.events.base import DomainEvent, EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.devices.api import DevicesAPI  # Fachada pública de Devices
from app.infrastructure.integrations.api import IntegrationsAPI  # Fachada de Infraestructura

from app.vdoms.exceptions import (
    VDOMAlreadyExistsError,
    VDOMIntegrationError,
    VDOMNotFoundError,
)
from app.vdoms.models import DeviceVDOM
from app.vdoms.repository import VDOMRepository
from app.vdoms.schemas import VDOMCreate, VDOMSyncResult, VDOMUpdate


class VDOMService:
    def __init__(self, db: AsyncSession, publisher: Optional[IEventPublisher] = None):
        self.db = db
        self.publisher = publisher
        self.vdom_repo = VDOMRepository(db)
        self.devices_api = DevicesAPI(db)
        self.clients_api = ClientsAPI(db)
        self.integrations_api = IntegrationsAPI()

    async def get_by_id_or_fail(self, vdom_id: uuid.UUID) -> DeviceVDOM:
        """Obtiene un VDOM o lanza una excepción de módulo."""
        vdom = await self.vdom_repo.get_by_id(vdom_id)
        if not vdom:
            raise VDOMNotFoundError()
        return vdom

    async def list_by_device(self, device_id: uuid.UUID) -> Sequence[DeviceVDOM]:
        """Lista VDOMs asociados a un dispositivo validando primero su existencia."""
        await self.devices_api.get_device_by_id(device_id)
        return await self.vdom_repo.list_by_device(device_id)

    async def create_vdom(
        self, data: VDOMCreate, metadata: Optional[EventMetadata] = None
    ) -> DeviceVDOM:
        """Crea un VDOM validando el cliente y evitando duplicados."""
        # 1. Validar existencia del dispositivo vía Fachada
        await self.devices_api.get_device_by_id(data.device_id)

        # 2. Validar cliente si viene especificado
        if data.client_id:
            await self.clients_api.validate_client_is_active(data.client_id)

        # 3. Validar duplicados por dispositivo y nombre
        existing_vdom = await self.vdom_repo.get_by_device_and_name(
            device_id=data.device_id, name=data.name
        )
        if existing_vdom:
            raise VDOMAlreadyExistsError()

        # 4. Crear entidad
        vdom = DeviceVDOM(
            device_id=data.device_id,
            client_id=data.client_id,
            name=data.name,
            is_root=data.is_root,
            is_active=data.is_active,
        )
        created_vdom = await self.vdom_repo.create(vdom)

        # 5. Publicar evento de dominio
        if self.publisher and metadata:
            event = DomainEvent(
                event_type="vdom.created",
                metadata=metadata,
                payload={
                    "vdom_id": str(created_vdom.id),
                    "vdom_name": created_vdom.name,
                    "device_id": str(created_vdom.device_id),
                    "client_id": str(created_vdom.client_id) if created_vdom.client_id else None,
                },
            )
            await self.publisher.publish(
                stream_or_topic=getattr(settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"),
                event=event,
            )

        return created_vdom

    async def sync_device_vdoms(
        self, device_id: uuid.UUID, metadata: Optional[EventMetadata] = None
    ) -> VDOMSyncResult:
        """Descubre y sincroniza VDOMs desde el hardware sin acoplar HTTP ni claves."""
        # 1. Obtener los datos de conexión resueltos por la fachada de dispositivos
        connection_data = await self.devices_api.get_connection_data(device_id)

        # 2. Invocar a la capa de integración
        try:
            raw_vdoms = await self.integrations_api.fortigate.list_vdoms(
                host=connection_data.host,
                port=connection_data.port,
                token=connection_data.decrypted_token,
            )
        except Exception as e:
            raise VDOMIntegrationError(
                message="Error al consultar los VDOMs en el dispositivo físico.",
                details={"error": str(e)},
            )

        new_count = 0
        unaltered_count = 0

        # 3. Mapear y procesar resultados en la base de datos
        for item in raw_vdoms:
            vdom_name = item.name if hasattr(item, "name") else item.get("name")
            if not vdom_name:
                continue

            existing = await self.vdom_repo.get_by_device_and_name(
                device_id=device_id, name=vdom_name
            )
            if existing:
                unaltered_count += 1
            else:
                new_vdom = DeviceVDOM(
                    device_id=device_id,
                    client_id=None,  # Nace sin cliente asignado hasta que se asigne manualmente
                    name=vdom_name,
                    is_root=(vdom_name.lower() == "root"),
                    is_active=True,
                )
                await self.vdom_repo.create(new_vdom)
                new_count += 1

        # 4. Publicar evento de sincronización
        if self.publisher and metadata:
            event = DomainEvent(
                event_type="vdom.synced",
                metadata=metadata,
                payload={"device_id": str(device_id), "discovered": len(raw_vdoms)},
            )
            await self.publisher.publish(
                stream_or_topic=getattr(settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"),
                event=event,
            )

        return VDOMSyncResult(
            device_id=device_id,
            total_found=len(raw_vdoms),
            new_registered=new_count,
            existing_unaltered=unaltered_count,
        )

    async def update_vdom(
        self, vdom_id: uuid.UUID, data: VDOMUpdate, metadata: Optional[EventMetadata] = None
    ) -> DeviceVDOM:
        """Actualiza cliente o estado del VDOM."""
        vdom = await self.get_by_id_or_fail(vdom_id)

        if data.client_id is not None:
            await self.clients_api.validate_client_is_active(data.client_id)
            vdom.client_id = data.client_id

        if data.is_active is not None:
            vdom.is_active = data.is_active

        updated_vdom = await self.vdom_repo.update(vdom)

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="vdom.updated",
                metadata=metadata,
                payload={
                    "vdom_id": str(updated_vdom.id),
                    "client_id": str(updated_vdom.client_id) if updated_vdom.client_id else None,
                    "is_active": updated_vdom.is_active,
                },
            )
            await self.publisher.publish(
                stream_or_topic=getattr(settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"),
                event=event,
            )

        return updated_vdom

    async def delete_vdom(
        self, vdom_id: uuid.UUID, metadata: Optional[EventMetadata] = None
    ) -> None:
        """Elimina un VDOM de la base de datos de la plataforma."""
        vdom = await self.get_by_id_or_fail(vdom_id)
        await self.vdom_repo.delete(vdom)

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="vdom.deleted",
                metadata=metadata,
                payload={"vdom_id": str(vdom_id), "name": vdom.name},
            )
            await self.publisher.publish(
                stream_or_topic=getattr(settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"),
                event=event,
            )