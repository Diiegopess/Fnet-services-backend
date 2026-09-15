from dataclasses import dataclass
from typing import Any, Dict, List

from app.services.hardening.models import FindingStatus
from app.services.hardening.strategies.base import BaseRule, RuleResult


@dataclass
class EvaluationSummary:
    """DTO con el resultado consolidado de la evaluación del motor."""

    score: float
    total_passed: int
    total_failed: int
    total_not_applicable: int
    findings: List[Dict[str, Any]]


class HardeningEvaluator:
    """Orquestador de evaluación que aplica N reglas sobre una configuración de FortiOS."""

    def evaluate_rules(
        self,
        rules: List[BaseRule],
        parsed_config: Dict[str, Any],
        target_platform: str = "fortigate",
    ) -> EvaluationSummary:

        passed = 0
        failed = 0
        not_applicable = 0

        findings: List[Dict[str, Any]] = []

        for rule in rules:
            # 1. Validar aplicabilidad por plataforma del dispositivo
            if target_platform not in rule.applicable_platforms:
                not_applicable += 1
                findings.append({
                    "rule_id": rule.rule_id,
                    "status": FindingStatus.NOT_APPLICABLE,
                    "severity": rule.default_severity,
                    "current_value": f"No aplicable a la plataforma '{target_platform}'",
                    "expected_value": None,
                    "remediation_cmd": None,
                })
                continue

            # 2. Ejecutar la evaluación de la regla
            try:
                result: RuleResult = rule.evaluate(parsed_config)
            except Exception as e:
                result = RuleResult(
                    status=FindingStatus.FAILED,
                    current_value=f"Error en motor de evaluación: {str(e)}",
                )

            # 3. Clasificar contadores
            if result.status == FindingStatus.PASSED:
                passed += 1
            elif result.status == FindingStatus.FAILED:
                failed += 1
            elif result.status == FindingStatus.NOT_APPLICABLE:
                not_applicable += 1

            # 4. Construir hallazgo
            findings.append({
                "rule_id": rule.rule_id,
                "status": result.status,
                "severity": rule.default_severity,
                "current_value": result.current_value,
                "expected_value": result.expected_value,
                "remediation_cmd": result.remediation_cmd,
            })

            # 5. Cálculo del Score (PASSED / (PASSED + FAILED))
            evaluable_total = passed + failed
            score = round((passed / evaluable_total) * 100.0, 2) if evaluable_total > 0 else 100.0

        return EvaluationSummary(
            score=score,
            total_passed=passed,
            total_failed=failed,
            total_not_applicable=not_applicable,
            findings=findings,
        )