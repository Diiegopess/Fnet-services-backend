"""
Dependencias para el Dominio de Dispositivos.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events.interfaces import IEventPublisher
from app.devices.service import DeviceService
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db

# Importación actualizada a la nueva ubicación del integrador
from app.infrastructure.integrations.fortinet.prober import FortinetProber


def get_device_prober() -> FortinetProber:
    """Inyector del prober desde la capa central de integraciones."""
    return FortinetProber()


def get_device_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
    prober: FortinetProber = Depends(get_device_prober),
) -> DeviceService:
    return DeviceService(db=db, publisher=publisher, prober=prober)