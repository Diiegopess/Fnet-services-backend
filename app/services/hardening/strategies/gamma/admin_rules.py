from typing import Any, Dict

from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


@register_rule
class BannerDisclaimerRule(BaseRule):
    """Gamma SAS Standard: Exigir banner de advertencia legal en el Login."""

    rule_id = "GAMMA-001"
    name = "Corporate Login Disclaimer Banner"
    description = "Valida que esté habilitado el mensaje de advertencia legal en el inicio de sesión."
    category = "Admin"
    standard = "GAMMA"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        pre_login_banner = system_global.get("pre-login-banner", "disable")

        if pre_login_banner == "enable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Banner activo (enable)",
                expected_value="enable",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value=f"Banner en '{pre_login_banner}'",
            expected_value="enable",
            remediation_cmd="config system global\n    set pre-login-banner enable\nend",
        )