"""
Fachada Pública del Módulo VDOMs para comunicación Inter-Módulos.
"""

import uuid
from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession

from app.vdoms.models import DeviceVDOM
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

    async def ensure_root_vdom(
        self, device_id: uuid.UUID, client_id: Optional[uuid.UUID] = None
    ) -> VDOMResponse:
        """
        Crea o asegura la existencia de la VDOM 'root' para un equipo.
        Utilizado por DeviceService al registrar hardware nuevo.
        """
        existing = await self.repository.get_by_device_and_name(
            device_id=device_id, name="root"
        )
        if existing:
            return VDOMResponse.model_validate(existing)

        root_vdom = DeviceVDOM(
            device_id=device_id,
            client_id=client_id,
            name="root",
            is_root=True,
            is_active=True,
        )
        created = await self.repository.create(root_vdom)
        return VDOMResponse.model_validate(created)