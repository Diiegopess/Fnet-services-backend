# app/services/hardening/dependencies.py

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.devices.api import DevicesAPI
from app.infrastructure.db.database import get_db
from app.services.hardening.repository import HardeningRepository
from app.services.hardening.service import HardeningService


def get_hardening_repository(
    db: AsyncSession = Depends(get_db),
) -> HardeningRepository:
    return HardeningRepository(session=db)


def get_hardening_service(
    repo: HardeningRepository = Depends(get_hardening_repository),
) -> HardeningService:
    # Se mantiene desacoplado para no romper GET /profiles
    return HardeningService(repository=repo)


def get_devices_api(
    db: AsyncSession = Depends(get_db),
) -> DevicesAPI:
    # Inyección limpia de la fachada de dispositivos
    return DevicesAPI(db=db)