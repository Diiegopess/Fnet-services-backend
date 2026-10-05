"""
Fachada Pública del Módulo Hardening para consumo Inter-Módulos.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.hardening.models import AuditReport, ExecutionType
from app.hardening.repository import HardeningRepository
from app.hardening.service import HardeningService
from app.vdoms.api import VDOMsAPI


class HardeningAPI:
    def __init__(self, session: AsyncSession):
        self.session = session
        self._repository = HardeningRepository(session=session)
        self._service = HardeningService(repository=self._repository)
        self._vdoms_api = VDOMsAPI(session=session)

    async def execute_device_audit(
        self,
        device_id: Optional[UUID] = None,
        raw_config: Optional[str] = None,
        execution_type: str = "FULL_STANDARD",
        profile_id: Optional[UUID] = None,
        adhoc_rule_ids: Optional[List[str]] = None,
        vdom_id: Optional[UUID] = None,
        connection_data: Optional[Dict[str, Any]] = None,
        standard_version: Optional[str] = None,
        executed_by: Optional[UUID] = None,
    ) -> AuditReport:
        """
        Ejecuta una auditoría de hardening delegando al servicio de dominio.
        Soporta auditoría en vivo (vía device_id y vdom_id) o análisis offline (vía raw_config).
        """
        # 1. Normalización y Mapeo del Enum de Dominio
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

        # 2. Resolución de VDOM objetivo si es auditoría en vivo sin VDOM explícita
        resolved_vdom_id = vdom_id
        if device_id and not raw_config and not resolved_vdom_id:
            root_vdom = await self._vdoms_api.ensure_root_vdom(device_id=device_id)
            resolved_vdom_id = root_vdom.id

        # 3. Delegación al servicio de hardening
        return await self._service.execute_audit(
            device_id=device_id,
            execution_type=exec_enum,
            connection_data=connection_data,
            raw_config=raw_config,
            profile_id=profile_id,
            adhoc_rule_ids=adhoc_rule_ids,
            standard_version=standard_version,
            vdom_id=resolved_vdom_id,
            executed_by=executed_by,
        )

    async def get_report_by_id(self, report_id: UUID) -> Optional[AuditReport]:
        """Consulta un reporte de auditoría por su identificador."""
        return await self._service.get_report_by_id(report_id)