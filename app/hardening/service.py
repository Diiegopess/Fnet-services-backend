# app/services/hardening/service.py

from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

from app.hardening.engine.evaluator import HardeningEvaluator
from app.hardening.exceptions import InvalidExecutionPayloadException
from app.hardening.models import AuditReport, ExecutionType, HardeningProfile
from app.hardening.repository import HardeningRepository
from app.hardening.parsers.fortios_conf_parser import FortiOSConfParser


class HardeningService:
    """Servicio principal de orquestación de Hardening declarativo."""

    def __init__(self, repository: HardeningRepository, fetcher=None):
        self.repository = repository
        self.evaluator = HardeningEvaluator()
        self.fetcher = fetcher

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

    # --- EJECUCIÓN DE AUDITORÍA DECLARATIVA ---

    async def execute_audit(
        self,
        device_id: UUID,
        execution_type: ExecutionType,
        connection_data: Optional[Dict[str, Any]] = None,
        raw_config: Optional[Dict[str, Any]] = None,
        profile_id: Optional[UUID] = None,
        adhoc_rule_ids: Optional[List[str]] = None,
        standard_version: Optional[str] = None,
        vdom_id: Optional[UUID] = None,
        executed_by: Optional[UUID] = None,
    ) -> AuditReport:
        """Orquesta la auditoría declarativa cargando reglas y aislando endpoints."""

        # 1. Determinar los IDs de reglas a ejecutar
        target_rule_ids: List[str] = []
        profile_rules = None

        if execution_type in (ExecutionType.FULL_STANDARD, ExecutionType.ASSIGNED_PROFILE):
            if not profile_id:
                raise InvalidExecutionPayloadException(
                    "Se requiere 'profile_id' para ejecuciones por estándar o perfil asignado."
                )
            profile = await self.repository.get_profile_by_id(profile_id)
            profile_rules = [
                rule for rule in profile.rules if getattr(rule, "is_active", True)
            ]
            target_rule_ids = [rule.id for rule in profile_rules]

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

        # 2. Para perfiles, conservar la versión de cada asociación (PK compuesta).
        # No volver a filtrar por la versión del request: perfiles antiguos pueden
        # tener una versión histórica en su cabecera, pero reglas versionadas válidas.
        if profile_rules is not None:
            rules_to_run = profile_rules
        else:
            rules_to_run = await self.repository.get_rules_by_ids(
                rule_ids=target_rule_ids, standard_version=standard_version
            )

        if not rules_to_run:
            raise InvalidExecutionPayloadException(
                "Ninguna de las reglas solicitadas existe o está activa en la base de datos."
            )

        # 3. EXTRACCIÓN DINÁMICA: Extraer endpoints desde las reglas cargadas
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

            # Deduplicar endpoints directamente de las entidades SQL cargadas
            required_endpoints = list({
                rule.required_endpoint
                for rule in rules_to_run
                if rule.required_endpoint
            })

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

        # 4. Evaluación declarativa
        summary = self.evaluator.evaluate_rules(
            rules=rules_to_run,
            parsed_config=parsed_config,
        )

        # 5. Persistir reporte en BD
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

    async def get_available_rules_catalog(
        self, standard: Optional[str] = None, standard_version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Devuelve el catálogo de reglas agrupado por categoría para el Frontend."""
        rules = await self.repository.get_all_active_rules(
            standard=standard, standard_version=standard_version
        )

        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for rule in rules:
            cat = rule.category.upper() if rule.category else "GENERAL"
            item = {
                "id": rule.id,
                "standard_version": rule.standard_version,
                "name": rule.name,
                "description": rule.description,
                "category": cat,
                "standard": rule.standard,
                "default_severity": rule.default_severity.value if hasattr(rule.default_severity, "value") else str(rule.default_severity),
                "required_endpoint": rule.required_endpoint,
                "is_active": rule.is_active,
            }
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(item)

        return [
            {"category": cat_name, "count": len(items), "rules": items}
            for cat_name, items in grouped.items()
        ]

    # --- AUDITORÍA DE ARCHIVO DE BACKUP (OFFLINE) ---

    async def evaluate_backup_file(
        self,
        file_content: str,
        profile_id: Optional[UUID] = None,
        standard_version: Optional[str] = None,
        adhoc_rule_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Evalúa un archivo .conf en memoria contra el catálogo de reglas seleccionado,
        devolviendo el resultado formateado para el frontend sin persistir en BD ni
        requerir conexión de red.
        """
        # 1. Determinar el catálogo de reglas a evaluar
        if profile_id:
            profile = await self.repository.get_profile_by_id(profile_id)
            if not profile:
                raise InvalidExecutionPayloadException(
                    "El perfil de hardening seleccionado no existe."
                )
            rules_to_run = [r for r in profile.rules if getattr(r, "is_active", True)]
        elif adhoc_rule_ids:
            rules_to_run = await self.repository.get_rules_by_ids(
                rule_ids=adhoc_rule_ids, standard_version=standard_version
            )
        else:
            # Evaluación completa por estándar si no se especificó un perfil o conjunto ad-hoc
            rules_to_run = await self.repository.get_all_active_rules(
                standard_version=standard_version
            )

        if not rules_to_run:
            raise InvalidExecutionPayloadException(
                "No se encontraron reglas activas para evaluar contra este archivo de backup."
            )

        # 2. Parsear el archivo .conf de FortiOS a la estructura CMDB esperada
        parser = FortiOSConfParser()
        parse_result = parser.parse(file_content)

        if not parse_result.cmdb_dump:
            raise InvalidExecutionPayloadException(
                "No se pudieron extraer secciones de configuración analizables del archivo de backup."
            )

        # 3. Ejecución directa sobre el motor declarativo existente
        summary = self.evaluator.evaluate_rules(
            rules=rules_to_run,
            parsed_config=parse_result.cmdb_dump,
        )

        # 4. Retornar payload compatible con el schema BackupAuditResponse
        return {
            "device_info": {
                "model": parse_result.metadata.model or "FortiGate",
                "firmware_version": parse_result.metadata.version or "Desconocida",
                "build": parse_result.metadata.build,
                "vdom_enabled": parse_result.metadata.vdom_enabled,
            },
            "score": summary.score,
            "total_passed": summary.total_passed,
            "total_partial": summary.total_partial,
            "total_failed": summary.total_failed,
            "total_not_applicable": summary.total_not_applicable,
            "findings": summary.findings,
        }

    
    