# app/services/hardening/engine/evaluator.py

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Union

from app.services.hardening.engine.declarative import DeclarativeRuleEngine
from app.services.hardening.models import FindingStatus, RuleCatalog, RuleSeverity
from app.services.hardening.strategies.base import RuleResult


@dataclass
class EvaluationSummary:
    """DTO con el resultado consolidado de la evaluación del motor."""

    score: float
    total_passed: int
    total_failed: int
    total_not_applicable: int
    findings: List[Dict[str, Any]]


class HardeningEvaluator:
    """Orquestador de evaluación desacoplado que procesa especificaciones JSON de BD."""

    def __init__(self):
        self.declarative_engine = DeclarativeRuleEngine()

    def evaluate_rules(
        self,
        rules: Sequence[Union[RuleCatalog, Dict[str, Any]]],
        parsed_config: Dict[str, Any],
    ) -> EvaluationSummary:

        passed = 0
        failed = 0
        not_applicable = 0

        total_compliance_sum = 0.0
        evaluable_rules_count = 0

        findings: List[Dict[str, Any]] = []

        for rule in rules:
            # 1. Normalizar metadatos de la regla (sea instancia SQLAlchemy o diccionario)
            if isinstance(rule, dict):
                rule_id = rule["id"]
                rule_version = rule.get("standard_version", "v1.0.0")
                rule_severity = rule.get("default_severity", RuleSeverity.MEDIUM)
                rule_spec = rule.get("rule_spec", {})
                required_endpoint = rule.get("required_endpoint", "")
            else:
                rule_id = rule.id
                rule_version = rule.standard_version
                rule_severity = rule.default_severity
                rule_spec = rule.rule_spec or {}
                required_endpoint = rule.required_endpoint

            rule_meta = {
                "id": rule_id,
                "standard_version": rule_version,
                "severity": rule_severity,
                "required_endpoint": required_endpoint,
            }

            # 2. Ejecutar evaluación declarativa aislando su endpoint
            try:
                result: RuleResult = self.declarative_engine.evaluate_rule(
                    rule_meta=rule_meta,
                    rule_spec=rule_spec,
                    raw_dump=parsed_config,
                )
            except Exception as e:
                result = RuleResult(
                    status=FindingStatus.FAILED,
                    compliance_score=0.0,
                    current_value=f"Error en ejecución declarativa: {str(e)}",
                    expected_value="Evaluación sin errores",
                )

            rule_score = result.compliance_score
            if rule_score is None:
                if result.status == FindingStatus.PASSED:
                    rule_score = 100.0
                elif result.status == FindingStatus.FAILED:
                    rule_score = 0.0
                else:
                    rule_score = 0.0

            rule_score = max(0.0, min(100.0, float(rule_score)))
            final_status = result.status

            # Evitar asignar estados no soportados por el Enum de la BD (como PARCIAL)
            if 0.0 < rule_score < 100.0 and final_status not in (
                FindingStatus.NOT_APPLICABLE,
                FindingStatus.PASSED,
            ):
                final_status = FindingStatus.FAILED

            # 4. Acumular estadísticas globales
            if final_status == FindingStatus.NOT_APPLICABLE:
                not_applicable += 1
            else:
                evaluable_rules_count += 1
                total_compliance_sum += rule_score

                if final_status == FindingStatus.PASSED:
                    passed += 1
                else:
                    failed += 1

            # 5. Hallazgo formateado para persistencia
            findings.append({
                "rule_id": rule_id,
                "standard_version": rule_version,
                "status": final_status,
                "compliance_score": round(rule_score, 2),
                "severity": rule_severity,
                "current_value": result.current_value,
                "expected_value": result.expected_value,
                "remediation_cmd": result.remediation_cmd or rule_spec.get("remediation_cmd"),
            })

        # 6. Cálculo del Score global
        score = (
            round(total_compliance_sum / evaluable_rules_count, 2)
            if evaluable_rules_count > 0
            else 100.0
        )

        return EvaluationSummary(
            score=score,
            total_passed=passed,
            total_failed=failed,
            total_not_applicable=not_applicable,
            findings=findings,
        )