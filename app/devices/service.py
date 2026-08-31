"""
Servicio de Negocio para el Dominio de Dispositivos (Chasis Fortinet).
"""

import uuid
from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI
from app.clients.exceptions import ClientNotFoundError
from app.core.events.base import EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.core.security import encrypt_secret
from app.devices.connectors.base import IDeviceProber
from app.devices.exceptions import DeviceAlreadyExistsError, DeviceNotFoundError
from app.devices.models import FortigateDevice
from app.devices.repository import DeviceRepository
from app.devices.schemas import ConnectivityCheckResult, DeviceCreate, DeviceUpdate
from app.devices.vdoms.models import DeviceVDOM
from app.devices.vdoms.repository import VDOMRepository


class DeviceService:
    def __init__(
        self,
        db: AsyncSession,
        publisher: IEventPublisher,
        prober: IDeviceProber,
    ):
        self.db = db
        self.publisher = publisher
        self.prober = prober
        self.repo = DeviceRepository(db)
        self.vdom_repo = VDOMRepository(db)
        self.clients_api = ClientsAPI(db)

    async def test_connectivity(self, host: str, port: int, api_token: str) -> ConnectivityCheckResult:
        """Prueba de diagnóstico desacoplada invocada a través del puerto IDeviceProber."""
        return await self.prober.probe(host=host, port=port, api_token=api_token)

    async def get_by_id_or_fail(self, device_id: uuid.UUID) -> FortigateDevice:
        device = await self.repo.get_by_id(device_id)
        if not device:
            raise DeviceNotFoundError()
        return device

    async def get_multi(self, skip: int = 0, limit: int = 50) -> Sequence[FortigateDevice]:
        return await self.repo.get_multi(skip=skip, limit=limit)

    async def create_device(self, data: DeviceCreate, metadata: EventMetadata) -> FortigateDevice:
        existing = await self.repo.get_by_host(data.host)
        if existing:
            raise DeviceAlreadyExistsError()

        # Validación del cliente por defecto si opera en modo standalone
        if not data.has_vdom_enabled:
            if not data.default_client_id:
                raise ClientNotFoundError("Se requiere 'default_client_id' para dispositivos en modo standalone/root.")
            if not await self.clients_api.is_client_active(data.default_client_id):
                raise ClientNotFoundError()

        # Intento de sonda no bloqueante para auto-descubrir serial real
        probe_result = await self.prober.probe(host=data.host, port=data.port, api_token=data.api_token)
        discovered_serial = probe_result.serial_number if probe_result.is_reachable else None

        encrypted_token = encrypt_secret(data.api_token)

        device = FortigateDevice(
            name=data.name,
            host=data.host,
            port=data.port,
            encrypted_api_token=encrypted_token,
            fortios_version=data.fortios_version,
            serial_number=discovered_serial,
            has_vdom_enabled=data.has_vdom_enabled,
            is_active=data.is_active,
        )
        created_device = await self.repo.create(device)

        # Creación automática del VDOM 'root' si el equipo opera en modo standalone
        if not data.has_vdom_enabled and data.default_client_id:
            root_vdom = DeviceVDOM(
                device_id=created_device.id,
                client_id=data.default_client_id,
                name="root",
                is_root=True,
                is_active=True,
            )
            await self.vdom_repo.create(root_vdom)
            created_device = await self.repo.get_by_id(created_device.id)

        await self.publisher.publish(
            stream_name="stream:system_events",
            event_type="device.created",
            payload={
                "device_id": str(created_device.id),
                "name": created_device.name,
                "host": created_device.host,
                "serial_number": created_device.serial_number,
                "has_vdom_enabled": created_device.has_vdom_enabled,
            },
            metadata=metadata,
        )

        return created_device

    async def update_device(self, device_id: uuid.UUID, data: DeviceUpdate, metadata: EventMetadata) -> FortigateDevice:
        device = await self.get_by_id_or_fail(device_id)

        if data.host and data.host != device.host:
            existing = await self.repo.get_by_host(data.host)
            if existing:
                raise DeviceAlreadyExistsError()
            device.host = data.host

        if data.name:
            device.name = data.name
        if data.port:
            device.port = data.port
        if data.fortios_version:
            device.fortios_version = data.fortios_version
        if data.has_vdom_enabled is not None:
            device.has_vdom_enabled = data.has_vdom_enabled
        if data.is_active is not None:
            device.is_active = data.is_active
        if data.api_token:
            device.encrypted_api_token = encrypt_secret(data.api_token)

        updated_device = await self.repo.update(device)

        await self.publisher.publish(
            stream_name="stream:system_events",
            event_type="device.updated",
            payload={"device_id": str(device_id), "name": updated_device.name},
            metadata=metadata,
        )

        return updated_device

    async def delete_device(self, device_id: uuid.UUID, metadata: EventMetadata) -> None:
        device = await self.get_by_id_or_fail(device_id)
        await self.repo.delete(device)

        await self.publisher.publish(
            stream_name="stream:system_events",
            event_type="device.deleted",
            payload={"device_id": str(device_id), "name": device.name},
            metadata=metadata,
        )