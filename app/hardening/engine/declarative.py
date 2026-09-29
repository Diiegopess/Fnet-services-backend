import json
import logging
from typing import Any, Dict, List, Optional

from app.hardening.engine.operators import OperatorRegistry
from app.hardening.models import FindingStatus
from app.hardening.strategies.base import RuleResult

logger = logging.getLogger(__name__)


class DeclarativeRuleEngine:
    """Motor de evaluación desacoplado que ejecuta aserciones JSON sobre el dump de FortiOS."""

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
    def _field_value(data: Dict[str, Any], field: Optional[str]) -> Any:
        if not field:
            return data
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
            return "No configurado / ausente"
        return str(value)

    def evaluate_rule(
        self,
        rule_meta: Dict[str, Any],
        rule_spec: Dict[str, Any],
        raw_dump: Dict[str, Any],
    ) -> RuleResult:
        """Evalúa una regla individual aislando estrictamente su endpoint del dump."""
        required_endpoint = (
            rule_spec.get("required_endpoint")
            or rule_meta.get("required_endpoint", "")
        ).lstrip("/")

        # 1. Validar presencia del endpoint en el dump
        endpoint_payload = raw_dump.get(required_endpoint)
        if not endpoint_payload or not isinstance(endpoint_payload, dict):
            return RuleResult(
                status=FindingStatus.NOT_APPLICABLE,
                compliance_score=0.0,
                current_value=f"Endpoint '{required_endpoint}' ausente o sin datos en el dump del dispositivo",
                expected_value="Respuesta HTTP 200 con datos válidos",
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
                current_value=f"No se encontró la clave '{target_path}' en la respuesta del endpoint",
                expected_value=f"Bloque de datos '{target_path}' presente",
                remediation_cmd=remediation,
            )

        # 2. Despacho por tipo de estructura
        if eval_type == "single_record":
            return self._evaluate_single_record(data_block, checks, rule_spec.get("any_of"), remediation)
        elif eval_type == "collection":
            return self._evaluate_collection(
                data=data_block,
                checks=checks,
                filter_spec=rule_spec.get("filter"),
                identifier_field=rule_spec.get("identifier_field", "name"),
                remediation=remediation,
                require_non_empty=rule_spec.get("require_non_empty", False),
            )
        else:
            return RuleResult(
                status=FindingStatus.FAILED,
                compliance_score=0.0,
                current_value=f"Tipo de evaluación no soportado: '{eval_type}'",
            )

    def _evaluate_single_record(self, data, checks, alternatives, remediation):
        total_units = len(checks) + (1 if alternatives else 0)
        passed_units = 0
        violations = []
        actual_values = []
        expected_values = []

        for check in checks:
            field = check.get("field")
            operator = check["operator"]
            expected = check.get("expected") if "expected" in check else check.get("forbidden")
            actual_val = self._field_value(data, field) if field else data

            actual_values.append(f"{field or 'root'}: {self._format_value(actual_val)}")
            expected_values.append(f"{field or 'root'} ({operator}): {self._format_value(expected)}")

            if OperatorRegistry.evaluate(operator, actual_val, expected):
                passed_units += 1
            else:
                desc = check.get("description", f"Fallo en campo '{field}'")
                violations.append(f"{desc}\n  Valor actual: {self._format_value(actual_val)}")

        if alternatives:
            alternative_passed = any(
                OperatorRegistry.evaluate(
                    alt["operator"],
                    self._field_value(data, alt["field"]) if alt.get("field") else data,
                    alt.get("expected") if "expected" in alt else alt.get("forbidden"),
                )
                for alt in alternatives
            )
            if alternative_passed:
                passed_units += 1
            else:
                violations.append("Ninguna de las condiciones opcionales (any_of) se cumplió.")

        score = (passed_units / total_units * 100) if total_units else 100.0

        if passed_units == total_units:
            status = FindingStatus.PASSED
        elif passed_units == 0:
            status = FindingStatus.FAILED
        else:
            status = FindingStatus.PARTIAL  # <- corregido: coincide con el enum real (español)

        return RuleResult(
            status=status,
            compliance_score=round(score, 2),
            current_value="\n\n".join(violations) if violations else "\n".join(actual_values),
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
        # Convertir diccionario de FortiOS a lista si viene indexado por llaves
        if isinstance(data, dict):
            data = [dict(item, _identifier=key) for key, item in data.items() if isinstance(item, dict)]

        if not isinstance(data, list):
            return RuleResult(
                status=FindingStatus.NOT_APPLICABLE,
                compliance_score=0.0,
                current_value="El bloque evaluado no es una lista o colección válida",
            )

        # Aplicar filtros si existen en la especificación
        items_to_audit = data
        if filter_spec:
            conditions = filter_spec.get("all_of", [filter_spec])
            items_to_audit = []
            for item in data:
                matches_all = True
                for cond in conditions:
                    target_field = cond.get("field")
                    expected_val = cond.get("value") if "value" in cond else cond.get("expected")
                    operator = cond.get("operator", "equals")

                    actual_val = self._field_value(item, target_field)
                    if not OperatorRegistry.evaluate(operator, actual_val, expected_val):
                        matches_all = False
                        break
                if matches_all:
                    items_to_audit.append(item)

        # Si tras el filtro no hay elementos
        if not items_to_audit:
            if require_non_empty:
                return RuleResult(
                    status=FindingStatus.FAILED,
                    compliance_score=0.0,
                    current_value="La colección está vacía y la regla exige al menos un elemento configurado",
                    expected_value="Al menos un registro coincidente",
                    remediation_cmd=remediation,
                )
            return RuleResult(
                status=FindingStatus.NOT_APPLICABLE,
                compliance_score=0.0,
                current_value="No se encontraron elementos en la colección que coincidan con el filtro",
                expected_value="Al menos un registro para evaluar",
            )

        violations = []
        compliant_items = 0
        total_items = len(items_to_audit)

        for item in items_to_audit:
            item_id = item.get(identifier_field, item.get("_identifier", "elemento"))
            item_ok = True

            for check in checks:
                operator = check["operator"]

                if "expected" in check:
                    expected = check["expected"]
                elif "forbidden" in check:
                    expected = check["forbidden"]
                else:
                    expected = check

                field = check.get("field")
                actual_val = self._field_value(item, field) if field else item

                if not OperatorRegistry.evaluate(operator, actual_val, expected):
                    item_ok = False
                    desc = check.get("description", f"Fallo en evaluación de '{operator}'")
                    violations.append(
                        f"[{item_id}] {desc}\n  Valor actual ({field or 'objeto'}): {self._format_value(actual_val)}"
                    )

            if item_ok:
                compliant_items += 1

        score = (compliant_items / total_items * 100) if total_items else 100.0

        if compliant_items == total_items:
            status = FindingStatus.PASSED
        elif compliant_items == 0:
            status = FindingStatus.FAILED
        else:
            status = FindingStatus.PARTIAL

        return RuleResult(
            status=status,
            compliance_score=round(score, 2),
            current_value=(
                "\n\n".join(violations)
                if violations
                else f"Todos los elementos evaluados ({total_items}) cumplen con la directriz"
            ),
            expected_value=f"{compliant_items}/{total_items} elementos conformes (100% requerido)",
            remediation_cmd=remediation,
        )