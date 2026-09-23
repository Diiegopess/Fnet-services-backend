# app/services/hardening/engine/declarative.py

import json
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

    @staticmethod
    def _field_value(data: Dict[str, Any], field: str) -> Any:
        current: Any = data
        for part in field.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    @staticmethod
    def _format_value(value: Any) -> str:
        if isinstance(value, (dict, list, tuple, set)):
            serializable = list(value) if isinstance(value, (tuple, set)) else value
            return json.dumps(serializable, ensure_ascii=False, indent=2, default=str)
        if value is None:
            return "No configurado"
        return str(value)

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
            return self._evaluate_single_record(data_block, checks, rule_spec.get("any_of"), remediation)
        elif eval_type == "collection":
            identifier_field = rule_spec.get("identifier_field", "name")
            filter_spec = rule_spec.get("filter")
            return self._evaluate_collection(
                data_block,
                checks,
                filter_spec,
                identifier_field,
                remediation,
                rule_spec.get("require_non_empty", False),
            )
        else:
            return RuleResult(
                status=FindingStatus.FAILED,
                compliance_score=0.0,
                current_value=f"Tipo de evaluación '{eval_type}' no reconocido",
            )

    def _evaluate_single_record(
        self,
        data: Dict[str, Any],
        checks: List[Dict[str, Any]],
        alternatives: Optional[List[Dict[str, Any]]],
        remediation: Optional[str],
    ) -> RuleResult:
        violations = []
        actual_values = []
        expected_values = []

        for check in checks:
            field = check["field"]
            operator = check["operator"]
            expected = check["expected"] if "expected" in check else check.get("forbidden")
            actual_val = self._field_value(data, field)

            actual_values.append(f"{field}: {self._format_value(actual_val)}")
            expected_values.append(f"{field} ({operator}): {self._format_value(expected)}")

            passes = OperatorRegistry.evaluate(operator, actual_val, expected)
            if not passes:
                desc = check.get("description", f"Fallo en campo '{field}'")
                violations.append(
                    f"{desc}\n  Valor actual ({field}): {self._format_value(actual_val)}"
                )

        if alternatives:
            alternative_passed = any(
                OperatorRegistry.evaluate(
                    alternative["operator"],
                    self._field_value(data, alternative["field"]),
                    alternative["expected"] if "expected" in alternative else alternative.get("forbidden"),
                )
                for alternative in alternatives
            )
            if not alternative_passed:
                violations.append("Ninguna de las condiciones alternativas se cumple")

        if violations:
            return RuleResult(
                status=FindingStatus.FAILED,
                compliance_score=0.0,
                current_value="\n\n".join(violations),
                expected_value="\n".join(expected_values),
                remediation_cmd=remediation,
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            compliance_score=100.0,
            current_value="\n".join(actual_values),
            expected_value="\n".join(expected_values),
            remediation_cmd=remediation,
        )

    def _evaluate_collection(
        self,
        data: Any,
        checks: List[Dict[str, Any]],
        filter_spec: Optional[Dict[str, Any]],
        identifier_field: str,
        remediation: Optional[str],
        require_non_empty: bool = False,
    ) -> RuleResult:
        if isinstance(data, dict):
            data = [dict(item, _identifier=key) for key, item in data.items() if isinstance(item, dict)]
        if not isinstance(data, list):
            return RuleResult(status=FindingStatus.NOT_APPLICABLE, compliance_score=0.0, current_value="El bloque evaluado no es una colección")

        # Aplicar filtro si la regla lo requiere (ej. solo interfaces con role == 'wan')
        items_to_audit = data
        if filter_spec:
            conditions = filter_spec.get("all_of", [filter_spec])
            items_to_audit = [
                item for item in data
                if all(
                    OperatorRegistry.evaluate(
                        condition.get("operator", "equals"),
                        self._field_value(item, condition["field"]),
                        condition.get("value") if "value" in condition else condition.get("expected"),
                    )
                    for condition in conditions
                )
            ]

        if not items_to_audit:
            if require_non_empty:
                return RuleResult(
                    status=FindingStatus.FAILED,
                    compliance_score=0.0,
                    current_value="La colección requerida está vacía",
                    expected_value="Al menos un elemento configurado",
                    remediation_cmd=remediation,
                )
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
            item_id = item.get(identifier_field, item.get("_identifier", "elemento"))
            for check in checks:
                operator = check["operator"]
                expected = check["expected"] if "expected" in check else check.get("forbidden")
                if operator == "not_both_contain":
                    actual_val = item
                    expected = {
                        "field_a": check["field_a"],
                        "field_b": check["field_b"],
                        "target_value": check["target_value"],
                    }
                else:
                    field = check["field"]
                    actual_val = self._field_value(item, field)

                passes = OperatorRegistry.evaluate(operator, actual_val, expected)
                if passes:
                    passed_evaluations += 1
                else:
                    desc = check.get("description", f"Fallo en {check.get('field', operator)}")
                    violations.append(
                        f"[{item_id}] {desc}\n  Valor actual: {self._format_value(actual_val)}"
                    )

        score = (passed_evaluations / total_evaluations) * 100.0 if total_evaluations > 0 else 0.0

        if violations:
            status = FindingStatus.FAILED if score == 0.0 else FindingStatus.PARCIAL
            return RuleResult(
                status=status,
                compliance_score=round(score, 2),
                current_value="\n\n".join(violations),
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