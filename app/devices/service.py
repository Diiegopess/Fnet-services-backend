"""
Servicio de Negocio para el Dominio de Dispositivos (Chasis Fortinet).
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI
from app.core.config import settings
from app.core.events.base import DomainEvent, EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.core.security import decrypt_secret, encrypt_secret
from app.infrastructure.integrations.fortinet.prober import FortinetProber
from app.devices.exceptions import DeviceAlreadyExistsError, DeviceNotFoundError
from app.devices.models import FortigateDevice
from app.devices.repository import DeviceRepository
from app.devices.schemas import ConnectivityCheckResult, DeviceCreate, DeviceUpdate
from app.vdoms.api import VDOMsAPI


class DeviceService:
    def __init__(
        self,
        db: AsyncSession,
        prober: Optional[FortinetProber] = None,
        publisher: Optional[IEventPublisher] = None,
    ):
        self.db = db
        self.prober = prober or FortinetProber()
        self.publisher = publisher
        self.repo = DeviceRepository(db)
        self.clients_api = ClientsAPI(db)
        self.vdoms_api = VDOMsAPI(db)

    def _sanitize_error_msg(self, msg: Optional[str]) -> Optional[str]:
        if not msg:
            return None
        return msg.encode("utf-8", errors="replace").decode("utf-8")

    async def test_connectivity(
        self, host: str, port: int, api_token: str
    ) -> ConnectivityCheckResult:
        result = await self.prober.probe(host=host, port=port, api_token=api_token)
        if not result.is_reachable and result.error_message:
            result.error_message = self._sanitize_error_msg(result.error_message)
        return result

    async def test_existing_device_connectivity(
        self, device_id: uuid.UUID
    ) -> ConnectivityCheckResult:
        device = await self.get_by_id_or_fail(device_id)
        decrypted_token = decrypt_secret(device.encrypted_api_token) if device.encrypted_api_token else ""
        return await self.test_connectivity(
            host=device.host,
            port=device.port,
            api_token=decrypted_token,
        )

    async def get_by_id_or_fail(self, device_id: uuid.UUID) -> FortigateDevice:
        device = await self.repo.get_by_id(device_id)
        if not device:
            raise DeviceNotFoundError()
        return device

    async def get_multi(
        self, 
        skip: int = 0, 
        limit: int = 50,
        client_id: Optional[uuid.UUID] = None,
    ) -> Sequence[FortigateDevice]:
        """Obtiene la lista de dispositivos delegando el filtro por cliente al repositorio."""
        return await self.repo.get_multi(skip=skip, limit=limit, client_id=client_id)

    async def create_device(
        self, data: DeviceCreate, metadata: Optional[EventMetadata] = None
    ) -> FortigateDevice:
        """Crea el hardware físico y asegura su VDOM root en una transacción atómica."""
        existing = await self.repo.get_by_host(data.host)
        if existing:
            raise DeviceAlreadyExistsError()

        # 1. Validar cliente si fue provisto
        if data.client_id:
            await self.clients_api.validate_client_is_active(data.client_id)

        # 2. Sondeo no bloqueante
        try:
            probe_result = await self.prober.probe(
                host=data.host, port=data.port, api_token=data.api_token
            )
            discovered_serial = (
                probe_result.serial_number if probe_result.is_reachable else None
            )
            detected_vdom_mode = (
                probe_result.vdom_mode if probe_result.is_reachable else None
            )
            has_vdom_enabled = (
                detected_vdom_mode == "multi-vdom"
                if detected_vdom_mode
                else data.has_vdom_enabled
            )
        except Exception:
            discovered_serial = None
            has_vdom_enabled = data.has_vdom_enabled

        encrypted_token = encrypt_secret(data.api_token)

        # 3. Persistir hardware físico
        device = FortigateDevice(
            name=data.name,
            host=data.host,
            port=data.port,
            encrypted_api_token=encrypted_token,
            fortios_version=data.fortios_version,
            serial_number=discovered_serial,
            has_vdom_enabled=has_vdom_enabled,
            is_active=data.is_active,
        )
        created_device = await self.repo.create(device)

        # 4. Invariante: Todo dispositivo nace con su VDOM root
        await self.vdoms_api.ensure_root_vdom(
            device_id=created_device.id,
            client_id=data.client_id,
        )

        # 5. Publicar evento de dominio
        if self.publisher and metadata:
            event = DomainEvent(
                event_type="device.created",
                metadata=metadata,
                payload={
                    "device_id": str(created_device.id),
                    "name": created_device.name,
                    "host": created_device.host,
                    "serial_number": created_device.serial_number,
                    "has_vdom_enabled": created_device.has_vdom_enabled,
                },
            )
            await self.publisher.publish(
                stream_or_topic=getattr(
                    settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"
                ),
                event=event,
            )

        return created_device

    async def update_device(
        self,
        device_id: uuid.UUID,
        data: DeviceUpdate,
        metadata: Optional[EventMetadata] = None,
    ) -> FortigateDevice:
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

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="device.updated",
                metadata=metadata,
                payload={"device_id": str(device_id), "name": updated_device.name},
            )
            await self.publisher.publish(
                stream_or_topic=getattr(
                    settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"
                ),
                event=event,
            )

        return updated_device

    async def delete_device(
        self, device_id: uuid.UUID, metadata: Optional[EventMetadata] = None
    ) -> None:
        device = await self.get_by_id_or_fail(device_id)
        await self.repo.delete(device)

        if self.publisher and metadata:
            event = DomainEvent(
                event_type="device.deleted",
                metadata=metadata,
                payload={"device_id": str(device_id), "name": device.name},
            )
            await self.publisher.publish(
                stream_or_topic=getattr(
                    settings, "SYSTEM_EVENTS_STREAM_NAME", "stream:system_events"
                ),
                event=event,
            )