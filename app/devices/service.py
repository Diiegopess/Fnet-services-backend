"""Servicio de Negocio para el Dominio de Dispositivos (Chasis Fortinet)."""

import uuid
from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.api import ClientsAPI, ClientNotFoundError
from app.core.config import settings
from app.core.events.base import DomainEvent, EventMetadata
from app.core.events.interfaces import IEventPublisher
from app.core.security import decrypt_secret, encrypt_secret 
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
        prober: IDeviceProber,
        publisher: Optional[IEventPublisher] = None,
    ):
        self.db = db
        self.prober = prober
        self.publisher = publisher
        self.repo = DeviceRepository(db)
        self.vdom_repo = VDOMRepository(db)
        self.clients_api = ClientsAPI(db)

    def _sanitize_error_msg(self, msg: Optional[str]) -> Optional[str]:
        """Garantiza la decodificación segura en UTF-8 para prevenir errores 'ascii codec'."""
        if not msg:
            return None
        return msg.encode("utf-8", errors="replace").decode("utf-8")

    async def test_connectivity(
        self, host: str, port: int, api_token: str
    ) -> ConnectivityCheckResult:
        """Prueba de diagnóstico desacoplada invocada a través del puerto IDeviceProber."""
        result = await self.prober.probe(
            host=host, port=port, api_token=api_token
        )

        if not result.is_reachable and result.error_message:
            result.error_message = self._sanitize_error_msg(
                result.error_message
            )

        return result

    async def test_existing_device_connectivity(
        self, device_id: uuid.UUID
    ) -> ConnectivityCheckResult:
        """Prueba de conectividad contra un equipo registrado usando el token almacenado."""
        device = await self.get_by_id_or_fail(device_id)
        
        # Descifrar el token persistido
        decrypted_token = decrypt_secret(device.encrypted_api_token)
        
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
        return await self.repo.get_multi(skip=skip, limit=limit, client_id=client_id)

    async def create_device(
        self, data: DeviceCreate, metadata: Optional[EventMetadata] = None
    ) -> FortigateDevice:
        existing = await self.repo.get_by_host(data.host)
        if existing:
            raise DeviceAlreadyExistsError()

        # 1. Validación del cliente en modo standalone/root
        if not data.has_vdom_enabled:
            if not data.client_id:
                raise ClientNotFoundError(
                    "Se requiere 'client_id' para dispositivos en modo standalone/root."
                )
            await self.clients_api.validate_client_is_active(data.client_id)

        # 2. Intento de sonda no bloqueante para descubrir serial real
        try:
            probe_result = await self.prober.probe(
                host=data.host, port=data.port, api_token=data.api_token
            )
            discovered_serial = (
                probe_result.serial_number
                if probe_result.is_reachable
                else None
            )
        except Exception:
            discovered_serial = None

        encrypted_token = encrypt_secret(data.api_token)

        # 3. Creación del dispositivo (se mapea client_id explícitamente)
        device = FortigateDevice(
            name=data.name,
            host=data.host,
            port=data.port,
            encrypted_api_token=encrypted_token,
            fortios_version=data.fortios_version,
            serial_number=discovered_serial,
            has_vdom_enabled=data.has_vdom_enabled,
            is_active=data.is_active,
            client_id=data.client_id,
        )
        created_device = await self.repo.create(device)

        # 4. Creación del VDOM 'root' desde el submódulo si opera en modo standalone
        if not data.has_vdom_enabled and data.client_id:
            root_vdom = DeviceVDOM(
                device_id=created_device.id,
                client_id=data.client_id,
                name="root",
                is_root=True,
                is_active=True,
            )
            await self.vdom_repo.create(root_vdom)
            created_device = await self.repo.get_by_id(created_device.id)

        # 5. Publicación de eventos de dominio
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
                    "client_id": str(created_device.client_id) if created_device.client_id else None,
                },
            )
            await self.publisher.publish(
                stream_or_topic=getattr(
                    settings,
                    "SYSTEM_EVENTS_STREAM_NAME",
                    "stream:system_events",
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
                payload={
                    "device_id": str(device_id),
                    "name": updated_device.name,
                },
            )
            await self.publisher.publish(
                stream_or_topic=getattr(
                    settings,
                    "SYSTEM_EVENTS_STREAM_NAME",
                    "stream:system_events",
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
                    settings,
                    "SYSTEM_EVENTS_STREAM_NAME",
                    "stream:system_events",
                ),
                event=event,
            )