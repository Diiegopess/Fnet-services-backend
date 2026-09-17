# app/services/hardening/api.py

from typing import List, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.hardening.models import AuditReport, ExecutionType
from app.services.hardening.repository import HardeningRepository
from app.services.hardening.service import HardeningService


class HardeningAPI:
    def __init__(self, session: AsyncSession):
        self._repository = HardeningRepository(session=session)
        self._service = HardeningService(repository=self._repository)

    async def execute_device_audit(
        self,
        device_id: UUID,
        raw_config: str,
        execution_type: str,
        profile_id: Optional[UUID] = None,
        adhoc_rule_ids: Optional[List[str]] = None,
        vdom_id: Optional[UUID] = None,
    ) -> AuditReport:
        
        # 1. Normalización y Mapeo de alias hacia los valores del Enum de Dominio
        type_str = execution_type.strip().upper()
        
        mapping = {
            "PROFILE": ExecutionType.ASSIGNED_PROFILE,
            "ASSIGNED_PROFILE": ExecutionType.ASSIGNED_PROFILE,
            "ADHOC": ExecutionType.CUSTOM_ADHOC,
            "CUSTOM_ADHOC": ExecutionType.CUSTOM_ADHOC,
            "FULL": ExecutionType.FULL_STANDARD,
            "FULL_STANDARD": ExecutionType.FULL_STANDARD,
        }

        exec_enum = mapping.get(type_str)

        if not exec_enum:
            raise ValueError(
                f"Tipo de ejecución '{execution_type}' no soportado. Valores válidos: {list(mapping.keys())}"
            )

        # 2. Delegación limpia al servicio del dominio
        return await self._service.execute_audit(
            device_id=device_id,
            raw_config=raw_config,
            execution_type=exec_enum,
            profile_id=profile_id,
            adhoc_rule_ids=adhoc_rule_ids,
            vdom_id=vdom_id,
        )