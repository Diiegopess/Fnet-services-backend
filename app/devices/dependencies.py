"""
Dependencias para el Dominio de Dispositivos.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.interfaces import IEventPublisher
from app.devices.connectors.base import IDeviceProber
from app.devices.connectors.prober import FortiOSHttpProber
from app.devices.service import DeviceService
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db


def get_device_prober() -> IDeviceProber:
    """Inyector del puerto IDeviceProber (permite swap por mock en tests)."""
    return FortiOSHttpProber(timeout_seconds=5.0)


def get_device_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
    prober: IDeviceProber = Depends(get_device_prober),
) -> DeviceService:
    return DeviceService(db=db, publisher=publisher, prober=prober)