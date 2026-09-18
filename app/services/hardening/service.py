# app/services/hardening/service.py

from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

from app.services.hardening.engine.evaluator import HardeningEvaluator
from app.services.hardening.exceptions import InvalidExecutionPayloadException
from app.services.hardening.models import AuditReport, ExecutionType, HardeningProfile
from app.services.hardening.repository import HardeningRepository
from app.services.hardening.strategies.base import BaseRule
from app.services.hardening.strategies.registry import RuleRegistry

import app.services.hardening.strategies  # Carga y registra las reglas automáticamente


class HardeningService:
    """Servicio principal de orquestación de Hardening (Evaluación por perfil/extracción quirúrgica)."""

    def __init__(self, repository: HardeningRepository, fetcher=None):
        self.repository = repository
        self.evaluator = HardeningEvaluator()
        self.fetcher = fetcher  # Inyección del FortinetConfigFetcher

    # --- CONSULTAS DE PERFILES ---

    async def list_profiles(
        self, standard_version: Optional[str] = None
    ) -> Sequence[HardeningProfile]:
        """Obtiene la lista de perfiles de hardening activos."""
        return await self.repository.get_all_profiles(standard_version=standard_version)

    async def get_profile_by_id(self, profile_id: UUID) -> HardeningProfile:
        """Obtiene el detalle de un perfil específico por su UUID."""
        return await self.repository.get_profile_by_id(profile_id)

    # --- CONSULTAS DE REPORTES ---

    async def list_reports(
        self,
        device_id: Optional[UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[AuditReport]:
        """Obtiene los reportes de auditoría guardados."""
        return await self.repository.get_reports(
            device_id=device_id, limit=limit, offset=offset
        )

    async def get_report_by_id(self, report_id: UUID) -> Optional[AuditReport]:
        """Obtiene el detalle de un reporte de auditoría por su UUID."""
        return await self.repository.get_report_by_id(report_id)

    # --- EJECUCIÓN DE AUDITORÍA ---

    async def execute_audit(
        self,
        device_id: UUID,
        execution_type: ExecutionType,
        connection_data: Optional[Dict[str, Any]] = None,
        raw_config: Optional[Dict[str, Any]] = None,
        profile_id: Optional[UUID] = None,
        adhoc_rule_ids: Optional[List[str]] = None,
        vdom_id: Optional[UUID] = None,
        executed_by: Optional[UUID] = None,
    ) -> AuditReport:
        """Orquesta la auditoría extrayendo únicamente los endpoints que el perfil exige."""

        # 1. Determinar los IDs de reglas a ejecutar
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

        if not target_rule_ids:
            raise InvalidExecutionPayloadException(
                "No se encontraron reglas configuradas para ejecutar en esta solicitud."
            )

        # 2. Instanciar las reglas registradas a evaluar
        unregistered_rule_ids = [
            rule_id for rule_id in target_rule_ids if not RuleRegistry.is_registered(rule_id)
        ]
        if unregistered_rule_ids:
            raise InvalidExecutionPayloadException(
                "Las siguientes reglas no están registradas en el motor: "
                + ", ".join(unregistered_rule_ids)
            )

        rules_to_run: List[BaseRule] = [
            RuleRegistry.get_rule(r_id) for r_id in target_rule_ids
        ]

        # 3. EXTRACCIÓN QUIRÚRGICA: Compilar endpoints directamente desde las reglas
        parsed_config: Dict[str, Any] = raw_config or {}

        if not parsed_config:
            if not self.fetcher:
                raise InvalidExecutionPayloadException(
                    "No se proporcionó 'raw_config' y el servicio 'fetcher' no está disponible."
                )
            if not connection_data:
                raise InvalidExecutionPayloadException(
                    "Se requieren los datos de conexión ('connection_data') para consultar el dispositivo."
                )

            # Resolver y deduplicar endpoints requeridos por las reglas a evaluar
            required_endpoints = list({
                rule.required_endpoint
                for rule in rules_to_run
                if getattr(rule, "required_endpoint", None)
            })

            # Extracción desde la infraestructura
            parsed_config = await self.fetcher.fetch_endpoints_data(
                host=connection_data["host"],
                port=connection_data["port"],
                api_token=connection_data["token"],
                endpoints=required_endpoints,
                vdom=connection_data.get("vdom"),
            )

        if not parsed_config:
            raise InvalidExecutionPayloadException(
                "No se obtuvo información de configuración para evaluar el dispositivo."
            )

        # 4. Ejecutar la evaluación del perfil (Calcula los % por regla y el % global)
        summary = self.evaluator.evaluate_rules(
            rules=rules_to_run,
            parsed_config=parsed_config,
        )

        # 5. Persistir el reporte en BD incluyendo compliance_score de cada hallazgo
        report = await self.repository.save_audit_report(
            device_id=device_id,
            vdom_id=vdom_id,
            execution_type=execution_type,
            profile_id=profile_id,
            score=summary.score,
            total_passed=summary.total_passed,
            total_failed=summary.total_failed,
            total_not_applicable=summary.total_not_applicable,
            findings_data=summary.findings,  # Cada dict dentro de list contiene "compliance_score"
            executed_by=executed_by,
        )

        return report

    async def get_available_rules_catalog(self) -> List[Dict[str, Any]]:
        """Devuelve todas las reglas registradas en el sistema agrupadas por estándar/categoría."""
        registered_rules = RuleRegistry.get_all_rules()

        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for rule in registered_rules:
            # Extraer estándar o categoría de la regla
            category = getattr(rule, "standard", getattr(rule, "category", "OTROS")).upper()

            rule_data = {
                "id": rule.rule_id,
                "name": getattr(rule, "name", rule.rule_id),
                "description": getattr(rule, "description", None),
                "category": category,
                "standard": getattr(rule, "standard", category),
                "default_severity": getattr(rule, "default_severity", "MEDIUM"),
                "is_active": True,
            }

            if category not in grouped:
                grouped[category] = []
            grouped[category].append(rule_data)

        # Retornar estructura en formato de lista de grupos para el frontend
        return [
            {"category": cat_name, "count": len(rules_list), "rules": rules_list}
            for cat_name, rules_list in grouped.items()
        ]