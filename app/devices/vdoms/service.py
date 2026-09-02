"""
Servicio de Negocio para el Subdominio de VDOMs.
"""

import uuid
from typing import Optional, Sequence
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI
from app.core.config import settings
from app.core.events.base import DomainEvent, EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.core.security import decrypt_secret
from app.devices.exceptions import DeviceNotFoundError, VDOMAlreadyExistsError, VDOMNotFoundError
from app.devices.repository import DeviceRepository
from app.devices.vdoms.models import DeviceVDOM
from app.devices.vdoms.repository import VDOMRepository
from app.devices.vdoms.schemas import VDOMCreate, VDOMSyncResult, VDOMUpdate


class VDOMService:
    def __init__(self, db: AsyncSession, publisher: Optional[IEventPublisher] = None):
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

    async def create_vdom(
        self, data: VDOMCreate, metadata: Optional[EventMetadata] = None
    ) -> DeviceVDOM:
        device = await self.device_repo.get_by_id(data.device_id)
        if not device:
            raise DeviceNotFoundError()

        # Validación desacoplada mediante fachada del módulo de clientes
        await self.clients_api.validate_client_is_active(data.client_id)

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

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="vdom.created",
                metadata=metadata,
                payload={
                    "vdom_id": str(created_vdom.id),
                    "vdom_name": created_vdom.name,
                    "device_id": str(created_vdom.device_id),
                    "client_id": str(created_vdom.client_id),
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
        """Descubre y sincroniza VDOMs desde el FortiGate físico."""
        device = await self.device_repo.get_by_id(device_id)
        if not device:
            raise DeviceNotFoundError()

        token = decrypt_secret(device.encrypted_api_token)
        is_mock_or_local = (
            "mock" in device.host.lower()
            or device.host in ("127.0.0.1", "localhost", "testserver")
            or device.port in (80, 8080)
        )
        scheme = "http" if is_mock_or_local else "https"
        url = f"{scheme}://{device.host}:{device.port}/api/v2/cmdb/system/vdom"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()

        raw_vdoms = data.get("results", [])
        existing_vdoms = {v.name: v for v in await self.vdom_repo.list_by_device(device_id)}

        new_count = 0
        unaltered_count = 0

        for item in raw_vdoms:
            vdom_name = item.get("name")
            if not vdom_name:
                continue

            if vdom_name in existing_vdoms:
                unaltered_count += 1
            else:
                new_vdom = DeviceVDOM(
                    device_id=device.id,
                    client_id=None,
                    name=vdom_name,
                    is_root=(vdom_name == "root"),
                    is_active=True,
                )
                await self.vdom_repo.create(new_vdom)
                new_count += 1

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
                    "client_id": str(updated_vdom.client_id),
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