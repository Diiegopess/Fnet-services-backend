from typing import Any, Dict

from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


@register_rule
class DisableHTTPAdminRule(BaseRule):
    """CIS Benchmark: Deshabilitar el acceso HTTP no cifrado para la administración."""

    rule_id = "CIS-1.1"
    name = "Disable HTTP Administration"
    description = "Garantiza que el protocolo HTTP esté deshabilitado para evitar tráfico en texto plano."
    category = "Network"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        admin_sport = system_global.get("admin-sport")  # Puerto HTTPS
        admin_port = system_global.get("admin-port")    # Puerto HTTP (si existe)

        # Si admin-port (HTTP) está explícitamente desactivado o ausente
        if admin_port == "0" or "admin-port" not in system_global:
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="HTTP Deshabilitado",
                expected_value="admin-port 0",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value=f"HTTP activo en puerto {admin_port}",
            expected_value="admin-port 0",
            remediation_cmd="config system global\n    set admin-port 0\nend",
        )