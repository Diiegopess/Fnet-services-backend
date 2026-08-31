"""
Dependencias HTTP para el Módulo de Clientes.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.service import ClientService
from app.core.events.interfaces import IEventPublisher
from app.infrastructure.brokers.factory import get_event_publisher
from app.infrastructure.db.database import get_db


def get_client_service(
    db: AsyncSession = Depends(get_db),
    publisher: IEventPublisher = Depends(get_event_publisher),
) -> ClientService:
    return ClientService(db=db, publisher=publisher)