from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.hardening.models import AuditReport, ExecutionType
from app.services.hardening.repository import HardeningRepository
from app.services.hardening.service import HardeningService


class HardeningFacade:
    """Fachada pública (Facade Pattern) para el módulo de Hardening."""

    def __init__(self, session: AsyncSession):
        self._repository = HardeningRepository(session=session)
        self._service = HardeningService(repository=self._repository)

    async def execute_device_audit(
        self,
        device_id: UUID,
        raw_config: str,
        execution_type: ExecutionType,
        profile_id: Optional[UUID] = None,
        vdom_id: Optional[UUID] = None,
    ) -> AuditReport:
        """Punto de entrada seguro para que otros servicios soliciten una auditoría."""
        return await self._service.execute_audit(
            device_id=device_id,
            raw_config=raw_config,
            execution_type=execution_type,
            profile_id=profile_id,
            vdom_id=vdom_id,
        )