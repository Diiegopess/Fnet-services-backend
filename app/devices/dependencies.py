"""
Dependencias para el Dominio de Dispositivos.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api import require_permission
from app.core.events.interfaces import IEventPublisher
from app.devices.permissions import DevicePermission
from app.devices.service import DeviceService
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db
from app.infrastructure.integrations.fortinet.prober import FortinetProber


def require_device_permission(permission: DevicePermission):
    """Dependency helper para validar permisos del dominio de dispositivos."""
    return require_permission(permission.value)


def get_device_prober() -> FortinetProber:
    """Inyector del prober desde la capa central de integraciones."""
    return FortinetProber()


def get_device_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
    prober: FortinetProber = Depends(get_device_prober),
) -> DeviceService:
    return DeviceService(db=db, publisher=publisher, prober=prober)