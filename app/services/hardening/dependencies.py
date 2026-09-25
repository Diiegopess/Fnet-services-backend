"""
Dependencias de FastAPI e Inyección de Contexto Autorizado para Hardening.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api import require_permission
from app.devices.api import DevicesAPI
from app.infrastructure.db.database import get_db
from app.infrastructure.integrations.fortinet.fetcher import FortinetConfigFetcher
from app.services.hardening.permissions import HardeningPermission
from app.services.hardening.repository import HardeningRepository
from app.services.hardening.service import HardeningService


def require_hardening_permission(permission: HardeningPermission):
    """Dependency helper para validar permisos del dominio de Hardening."""
    return require_permission(permission.value)


def get_hardening_repository(
    db: AsyncSession = Depends(get_db),
) -> HardeningRepository:
    return HardeningRepository(session=db)


def get_hardening_service(
    repo: HardeningRepository = Depends(get_hardening_repository),
) -> HardeningService:
    fetcher = FortinetConfigFetcher(timeout_seconds=30.0)
    return HardeningService(repository=repo, fetcher=fetcher)


def get_devices_api(
    db: AsyncSession = Depends(get_db),
) -> DevicesAPI:
    return DevicesAPI(db=db)