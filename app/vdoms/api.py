"""
Fachada Pública del Módulo VDOMs para comunicación Inter-Módulos.
"""

import uuid
from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.vdoms.repository import VDOMRepository
from app.vdoms.schemas import VDOMResponse


class VDOMsAPI:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repository = VDOMRepository(db)

    async def get_vdom_by_id(self, vdom_id: uuid.UUID) -> VDOMResponse | None:
        """Obtiene un VDOM mapeado a DTO por su ID."""
        vdom = await self.repository.get_by_id(vdom_id)
        if not vdom:
            return None
        return VDOMResponse.model_validate(vdom)

    async def list_vdoms_by_client_ids(self, client_ids: list[uuid.UUID]) -> Sequence[VDOMResponse]:
        """Obtiene los VDOMs activos asociados a una lista de IDs de clientes."""
        vdoms = await self.repository.list_by_client_ids(client_ids)
        return [VDOMResponse.model_validate(v) for v in vdoms]