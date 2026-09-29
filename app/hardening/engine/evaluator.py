import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Union

from app.hardening.engine.declarative import DeclarativeRuleEngine
from app.hardening.models import FindingStatus, RuleCatalog, RuleSeverity
from app.hardening.strategies.base import RuleResult

logger = logging.getLogger(__name__)

# Umbral mínimo de cumplimiento para que un hallazgo con score intermedio
# se clasifique como PARCIAL. Por debajo de este valor, se reclasifica
# como FAILED aunque el motor declarativo haya calculado algo de score.
# Vive aquí (capa de negocio) y no en declarative.py (capa de cálculo puro)
# para poder ajustarlo sin tocar el motor de evaluación.
PARTIAL_COMPLIANCE_THRESHOLD = 35.0


@dataclass
class EvaluationSummary:
    """DTO con el resultado consolidado de la evaluación del motor."""

    score: float
    total_passed: int
    total_partial: int
    total_failed: int
    total_not_applicable: int
    findings: List[Dict[str, Any]] = field(default_factory=list)


class HardeningEvaluator:
    """Orquestador de evaluación desacoplado que procesa especificaciones JSON de BD."""

    def __init__(self, partial_threshold: float = PARTIAL_COMPLIANCE_THRESHOLD):
        self.declarative_engine = DeclarativeRuleEngine()
        self.partial_threshold = partial_threshold

    def evaluate_rules(
        self,
        rules: Sequence[Union[RuleCatalog, Dict[str, Any]]],
        parsed_config: Dict[str, Any],
    ) -> EvaluationSummary:

        passed = 0
        partial = 0
        failed = 0
        not_applicable = 0

        total_compliance_sum = 0.0
        evaluable_rules_count = 0

        findings: List[Dict[str, Any]] = []

        for rule in rules:
            # 1. Normalizar metadatos de la regla
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

            # 2. Ejecutar evaluación declarativa
            try:
                result: RuleResult = self.declarative_engine.evaluate_rule(
                    rule_meta=rule_meta,
                    rule_spec=rule_spec,
                    raw_dump=parsed_config,
                )
            except Exception as e:
                logger.error(f"Error evaluando la regla {rule_id}: {str(e)}", exc_info=True)
                result = RuleResult(
                    status=FindingStatus.FAILED,
                    compliance_score=0.0,
                    current_value=f"Error interno de especificación/ejecución: {str(e)}",
                    expected_value="Sintaxis de regla y ejecución válida",
                )

            final_status = result.status
            rule_score = result.compliance_score

            # 3. Aplicar umbral de negocio sobre resultados PARCIALES.
            #    El motor declarativo no conoce política de negocio: solo
            #    calcula el score real. Aquí decidimos si ese score parcial
            #    es "suficientemente parcial" para contar como PARCIAL,
            #    o si es tan bajo que debe tratarse como FAILED.
            if final_status == FindingStatus.PARTIAL and rule_score < self.partial_threshold:
                final_status = FindingStatus.FAILED

            # 4. Acumular estadísticas globales
            if final_status == FindingStatus.NOT_APPLICABLE:
                not_applicable += 1
            else:
                evaluable_rules_count += 1
                total_compliance_sum += rule_score

                if final_status == FindingStatus.PASSED:
                    passed += 1
                elif final_status == FindingStatus.PARTIAL:
                    partial += 1
                else:
                    failed += 1

            # 5. Registrar hallazgo (con el status ya reclasificado según el umbral)
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
            total_partial=partial,
            total_failed=failed,
            total_not_applicable=not_applicable,
            findings=findings,
        )