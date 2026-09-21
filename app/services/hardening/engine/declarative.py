# app/services/hardening/engine/declarative.py

from typing import Any, Dict, List, Optional
from app.services.hardening.engine.operators import OperatorRegistry
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import RuleResult


class DeclarativeRuleEngine:
    """Motor de evaluación desacoplado que ejecuta aserciones JSON sobre el dump."""

    @staticmethod
    def _extract_nested(data: Dict[str, Any], path: Optional[str]) -> Any:
        if not path:
            return data
        current = data
        for part in path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def evaluate_rule(
        self,
        rule_meta: Dict[str, Any],
        rule_spec: Dict[str, Any],
        raw_dump: Dict[str, Any],
    ) -> RuleResult:
        """Evalúa una regla individual aislando estrictamente su endpoint del dump.
        
        :param rule_meta: Metadatos de la regla (id, severity, etc.)
        :param rule_spec: Especificación JSONB de la regla
        :param raw_dump: Diccionario completo de respuestas del fetcher
        """
        required_endpoint = (
            rule_spec.get("required_endpoint") 
            or rule_meta.get("required_endpoint", "")
        ).lstrip("/")

        # 1. Aislamiento de contexto: solo leer la respuesta del endpoint solicitado
        endpoint_payload = raw_dump.get(required_endpoint)
        if not endpoint_payload or not isinstance(endpoint_payload, dict):
            return RuleResult(
                status=FindingStatus.NOT_APPLICABLE,
                compliance_score=0.0,
                current_value=f"Endpoint '{required_endpoint}' ausente o vacío en el dump",
                expected_value="Respuesta HTTP 200 con estructura de datos válida",
            )

        eval_type = rule_spec.get("type", "single_record")
        target_path = rule_spec.get("target_path", "results")
        checks = rule_spec.get("checks", [])
        remediation = rule_spec.get("remediation_cmd")

        data_block = self._extract_nested(endpoint_payload, target_path)
        if data_block is None:
            return RuleResult(
                status=FindingStatus.FAILED,
                compliance_score=0.0,
                current_value=f"No se encontró el bloque '{target_path}' en la respuesta",
                expected_value=f"Bloque de datos '{target_path}' presente",
                remediation_cmd=remediation,
            )

        # 2. Evaluación por tipo de estructura
        if eval_type == "single_record":
            return self._evaluate_single_record(data_block, checks, remediation)
        elif eval_type == "collection":
            identifier_field = rule_spec.get("identifier_field", "name")
            filter_spec = rule_spec.get("filter")
            return self._evaluate_collection(data_block, checks, filter_spec, identifier_field, remediation)
        else:
            return RuleResult(
                status=FindingStatus.FAILED,
                compliance_score=0.0,
                current_value=f"Tipo de evaluación '{eval_type}' no reconocido",
            )

    def _evaluate_single_record(
        self, data: Dict[str, Any], checks: List[Dict[str, Any]], remediation: Optional[str]
    ) -> RuleResult:
        violations = []
        actual_values = []
        expected_values = []

        for check in checks:
            field = check["field"]
            operator = check["operator"]
            expected = check.get("expected") or check.get("forbidden")
            actual_val = data.get(field)

            actual_values.append(f"{field}: {actual_val}")
            expected_values.append(f"{field} ({operator}): {expected}")

            passes = OperatorRegistry.evaluate(operator, actual_val, expected)
            if not passes:
                desc = check.get("description", f"Fallo en campo '{field}'")
                violations.append(f"{desc} (Valor actual: '{actual_val}')")

        if violations:
            return RuleResult(
                status=FindingStatus.FAILED,
                compliance_score=0.0,
                current_value="; ".join(violations),
                expected_value="; ".join(expected_values),
                remediation_cmd=remediation,
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            compliance_score=100.0,
            current_value="; ".join(actual_values),
            expected_value="; ".join(expected_values),
            remediation_cmd=remediation,
        )

    def _evaluate_collection(
        self,
        data: Any,
        checks: List[Dict[str, Any]],
        filter_spec: Optional[Dict[str, Any]],
        identifier_field: str,
        remediation: Optional[str],
    ) -> RuleResult:
        if not isinstance(data, list):
            return RuleResult(
                status=FindingStatus.NOT_APPLICABLE,
                compliance_score=0.0,
                current_value="El bloque evaluado no es una lista de elementos",
            )

        # Aplicar filtro si la regla lo requiere (ej. solo interfaces con role == 'wan')
        items_to_audit = data
        if filter_spec:
            f_field = filter_spec["field"]
            f_op = filter_spec.get("operator", "equals")
            f_val = filter_spec["value"]
            items_to_audit = [
                item for item in data
                if OperatorRegistry.evaluate(f_op, item.get(f_field), f_val)
            ]

        if not items_to_audit:
            return RuleResult(
                status=FindingStatus.NOT_APPLICABLE,
                compliance_score=100.0,
                current_value="No existen elementos en la lista que cumplan el criterio de filtro",
                expected_value="Al menos un elemento coincidente para auditar",
            )

        violations = []
        total_evaluations = len(items_to_audit) * len(checks)
        passed_evaluations = 0

        for item in items_to_audit:
            item_id = item.get(identifier_field, "elemento")
            for check in checks:
                field = check["field"]
                operator = check["operator"]
                expected = check.get("expected") or check.get("forbidden")
                actual_val = item.get(field)

                passes = OperatorRegistry.evaluate(operator, actual_val, expected)
                if passes:
                    passed_evaluations += 1
                else:
                    desc = check.get("description", f"Fallo en {field}")
                    violations.append(f"[{item_id}] {desc} (Valor: '{actual_val}')")

        score = (passed_evaluations / total_evaluations) * 100.0 if total_evaluations > 0 else 0.0

        if violations:
            status = FindingStatus.FAILED if score == 0.0 else FindingStatus.PARCIAL
            return RuleResult(
                status=status,
                compliance_score=round(score, 2),
                current_value="; ".join(violations),
                expected_value=f"Todos los elementos deben satisfacer las condiciones definidas ({len(items_to_audit)} auditados)",
                remediation_cmd=remediation,
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            compliance_score=100.0,
            current_value=f"Todos los elementos ({len(items_to_audit)}) cumplen con la política",
            expected_value="Todos conformes",
            remediation_cmd=remediation,
        )