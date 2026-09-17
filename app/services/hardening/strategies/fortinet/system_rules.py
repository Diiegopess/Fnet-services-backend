from typing import Any, Dict

from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


@register_rule
class CustomAdminPortRule(BaseRule):
    """Fortinet Best Practices: Cambiar puerto HTTPS por defecto (443)."""

    rule_id = "FORTI-001"
    name = "Custom HTTPS Admin Port"
    description = "Evita exponer la consola de gestión en el puerto por defecto 443."
    category = "System"
    standard = "FORTINET"
    standard_version = "v1.0.0"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        admin_sport = system_global.get("admin-sport", "443")

        if admin_sport != "443":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value=f"Puerto HTTPS personalizado: {admin_sport}",
                expected_value="!= 443",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value="Puerto 443 (Por defecto)",
            expected_value="Diferente de 443 (Ej. 8443)",
            remediation_cmd="config system global\n    set admin-sport 8443\nend",
        )