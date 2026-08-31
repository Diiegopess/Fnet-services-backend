"""
Servicio de Negocio para el Subdominio de VDOMs.
"""

import uuid
from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI
from app.clients.exceptions import ClientNotFoundError
from app.core.events.base import EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.devices.exceptions import DeviceNotFoundError, VDOMAlreadyExistsError, VDOMNotFoundError
from app.devices.models import FortigateDevice
from app.devices.repository import DeviceRepository
from app.devices.vdoms.models import DeviceVDOM
from app.devices.vdoms.repository import VDOMRepository
from app.devices.vdoms.schemas import VDOMCreate, VDOMUpdate


class VDOMService:
    def __init__(self, db: AsyncSession, publisher: IEventPublisher):
        self.db = db
        self.publisher = publisher
        self.vdom_repo = VDOMRepository(db)
        self.device_repo = DeviceRepository(db)
        self.clients_api = ClientsAPI(db)

    async def get_by_id_or_fail(self, vdom_id: uuid.UUID) -> DeviceVDOM:
        vdom = await self.vdom_repo.get_by_id_with_device(vdom_id)
        if not vdom:
            raise VDOMNotFoundError()
        return vdom

    async def list_by_device(self, device_id: uuid.UUID) -> Sequence[DeviceVDOM]:
        device = await self.device_repo.get_by_id(device_id)
        if not device:
            raise DeviceNotFoundError()
        return await self.vdom_repo.list_by_device(device_id)

    async def create_vdom(self, data: VDOMCreate, metadata: EventMetadata) -> DeviceVDOM:
        device = await self.device_repo.get_by_id(data.device_id)
        if not device:
            raise DeviceNotFoundError()

        if not await self.clients_api.is_client_active(data.client_id):
            raise ClientNotFoundError("El cliente asociado no existe o está inactivo.")

        existing_vdoms = await self.vdom_repo.list_by_device(data.device_id)
        if any(v.name.lower() == data.name.lower() for v in existing_vdoms):
            raise VDOMAlreadyExistsError()

        vdom = DeviceVDOM(
            device_id=data.device_id,
            client_id=data.client_id,
            name=data.name,
            is_root=data.is_root,
            is_active=data.is_active,
        )
        created_vdom = await self.vdom_repo.create(vdom)

        # Disparar evento de auditoría
        await self.publisher.publish(
            stream_name="stream:system_events",
            event_type="vdom.created",
            payload={
                "vdom_id": str(created_vdom.id),
                "vdom_name": created_vdom.name,
                "device_id": str(created_vdom.device_id),
                "client_id": str(created_vdom.client_id),
            },
            metadata=metadata,
        )

        return created_vdom

    async def update_vdom(self, vdom_id: uuid.UUID, data: VDOMUpdate, metadata: EventMetadata) -> DeviceVDOM:
        vdom = await self.get_by_id_or_fail(vdom_id)

        if data.client_id is not None:
            if not await self.clients_api.is_client_active(data.client_id):
                raise ClientNotFoundError("El nuevo cliente asociado no existe o está inactivo.")
            vdom.client_id = data.client_id

        if data.is_active is not None:
            vdom.is_active = data.is_active

        self.db.add(vdom)
        await self.db.commit()
        await self.db.refresh(vdom)

        await self.publisher.publish(
            stream_name="stream:system_events",
            event_type="vdom.updated",
            payload={"vdom_id": str(vdom.id), "client_id": str(vdom.client_id), "is_active": vdom.is_active},
            metadata=metadata,
        )

        return vdom

    async def delete_vdom(self, vdom_id: uuid.UUID, metadata: EventMetadata) -> None:
        vdom = await self.get_by_id_or_fail(vdom_id)
        await self.vdom_repo.delete(vdom)

        await self.publisher.publish(
            stream_name="stream:system_events",
            event_type="vdom.deleted",
            payload={"vdom_id": str(vdom_id), "name": vdom.name},
            metadata=metadata,
        )