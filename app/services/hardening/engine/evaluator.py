# app/services/hardening/engine/evaluator.py

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
    """Orquestador de evaluación que aplica N reglas sobre respuestas JSON/CMDB de FortiOS."""

    def evaluate_rules(
        self,
        rules: List[BaseRule],
        parsed_config: Dict[str, Any],
        target_platform: str = "fortigate",
    ) -> EvaluationSummary:

        passed = 0
        failed = 0
        not_applicable = 0

        total_compliance_sum = 0.0
        evaluable_rules_count = 0

        findings: List[Dict[str, Any]] = []

        for rule in rules:
            # 1. Validar aplicabilidad por plataforma del dispositivo
            if target_platform not in rule.applicable_platforms:
                not_applicable += 1
                findings.append({
                    "rule_id": rule.rule_id,
                    "status": FindingStatus.NOT_APPLICABLE,
                    "compliance_score": 0.0,
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
                    compliance_score=0.0,
                    current_value=f"Error en motor de evaluación: {str(e)}",
                )

            # 3. Determinar el porcentaje de cumplimiento de la regla
            rule_score = result.compliance_score
            if rule_score is None:
                if result.status == FindingStatus.PASSED:
                    rule_score = 100.0
                elif result.status == FindingStatus.FAILED:
                    rule_score = 0.0
                else:
                    rule_score = 0.0

            # Normalizar el valor dentro del rango 0 - 100
            rule_score = max(0.0, min(100.0, float(rule_score)))

            # Clasificar status visual si la regla devolvió un score parcial
            final_status = result.status
            if 0.0 < rule_score < 100.0 and result.status not in (FindingStatus.NOT_APPLICABLE, FindingStatus.PARTIAL):
                final_status = FindingStatus.PARTIAL

            # 4. Acumular estadísticas globales
            if result.status == FindingStatus.NOT_APPLICABLE:
                not_applicable += 1
            else:
                evaluable_rules_count += 1
                total_compliance_sum += rule_score

                if final_status == FindingStatus.PASSED:
                    passed += 1
                else:
                    # Tanto FAILED como PARTIAL cuentan como fallidos/no totalmente aprobados
                    failed += 1

            # 5. Construir hallazgo
            findings.append({
                "rule_id": rule.rule_id,
                "status": final_status,
                "compliance_score": round(rule_score, 2),
                "severity": rule.default_severity,
                "current_value": result.current_value,
                "expected_value": result.expected_value,
                "remediation_cmd": result.remediation_cmd,
            })

        # 6. Cálculo del Score global del perfil/auditoría (Promedio de porcentajes)
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