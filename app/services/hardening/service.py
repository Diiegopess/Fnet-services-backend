from typing import List, Optional, Sequence
from uuid import UUID

from app.services.hardening.engine.evaluator import HardeningEvaluator
from app.services.hardening.engine.parser import FortiOSParser
from app.services.hardening.exceptions import InvalidExecutionPayloadException
from app.services.hardening.models import (
    AuditReport,
    ExecutionType,
    HardeningProfile,
)
from app.services.hardening.repository import HardeningRepository
from app.services.hardening.strategies.base import BaseRule
from app.services.hardening.strategies.registry import RuleRegistry

import app.services.hardening.strategies

class HardeningService:
    """Servicio principal de orquestación de Hardening (Evaluación pura por CLI Dump)."""

    def __init__(self, repository: HardeningRepository):
        self.repository = repository
        self.evaluator = HardeningEvaluator()

    async def list_profiles(
        self, standard_version: Optional[str] = None
    ) -> Sequence[HardeningProfile]:
        """Este método solo usa self.repository, no debería fallar."""
        return await self.repository.get_all_profiles(standard_version=standard_version)
    
    async def execute_audit(
        self,
        device_id: UUID,
        execution_type: ExecutionType,
        raw_config: Optional[str] = None, # 👈 Ahora es opcional
        profile_id: Optional[UUID] = None,
        adhoc_rule_ids: Optional[List[str]] = None,
        vdom_id: Optional[UUID] = None,
        executed_by: Optional[UUID] = None,
    ) -> AuditReport:
        """Orquesta la auditoría parseando el CLI Dump provisto."""

        if not raw_config or not raw_config.strip():
            raise InvalidExecutionPayloadException(
                "No se recibió la configuración en texto plano para evaluar el dispositivo."
            )

        # 1. Determinar qué IDs de reglas se deben evaluar
        target_rule_ids: List[str] = []

        if execution_type in (ExecutionType.FULL_STANDARD, ExecutionType.ASSIGNED_PROFILE):
            if not profile_id:
                raise InvalidExecutionPayloadException(
                    "Se requiere 'profile_id' para ejecuciones por estándar o perfil asignado."
                )
            target_rule_ids = await self.repository.get_profile_rule_ids(profile_id)

        elif execution_type == ExecutionType.CUSTOM_ADHOC:
            if not adhoc_rule_ids:
                raise InvalidExecutionPayloadException(
                    "Se requiere la lista 'adhoc_rule_ids' para un escaneo personalizado."
                )
            target_rule_ids = adhoc_rule_ids

        # 2. Instanciar las reglas registradas
        rules_to_run: List[BaseRule] = []
        for r_id in target_rule_ids:
            if RuleRegistry.is_registered(r_id):
                rules_to_run.append(RuleRegistry.get_rule(r_id))

        # 3. Parsear la configuración CLI Dump pura
        parsed_config = FortiOSParser.parse_cli(raw_config)

        # 4. Ejecutar la evaluación en el Engine
        summary = self.evaluator.evaluate_rules(
            rules=rules_to_run,
            parsed_config=parsed_config,
        )

        # 5. Persistir el reporte e historial en BD
        report = await self.repository.save_audit_report(
            device_id=device_id,
            vdom_id=vdom_id,
            execution_type=execution_type,
            profile_id=profile_id,
            score=summary.score,
            total_passed=summary.total_passed,
            total_failed=summary.total_failed,
            total_not_applicable=summary.total_not_applicable,
            findings_data=summary.findings,
            executed_by=executed_by,
        )

        return report

    async def list_reports(
        self,
        device_id: Optional[UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[AuditReport]:
        """Consulta el historial de reportes de auditoría guardados."""
        return await self.repository.get_reports(
            device_id=device_id,
            limit=limit,
            offset=offset,
        )

    async def get_report_by_id(self, report_id: UUID) -> Optional[AuditReport]:
        """Obtiene un reporte de auditoría específico por su ID."""
        return await self.repository.get_report_by_id(report_id)