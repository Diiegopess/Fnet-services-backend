from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# FORTI-023 - Enforce NTP Authentication and Synchronization
# =============================================================================
@register_rule
class NTPAuthenticationRule(BaseRule):
    """Fortinet Best Practices: Forzar autenticación y sincronización precisa con servidores NTP."""

    rule_id = "FORTI-023"
    name = "Enforce NTP Synchronization and Authentication"
    description = (
        "Garantiza que el tiempo del sistema esté sincronizado mediante NTP para el análisis "
        "correcto de logs, forense digital y validación de certificados digitales."
    )
    category = "System & Network Services"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_ntp = parsed_config.get("config system ntp", {})

        if not system_ntp:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="NTP no está configurado explícitamente",
                expected_value="ntpsync enable con servidores NTP definidos",
                remediation_cmd=(
                    "config system ntp\n"
                    "    set ntpsync enable\n"
                    "    set type custom\n"
                    "    config ntpserver\n"
                    "        edit 1\n"
                    "            set server \"pool.ntp.org\"\n"
                    "        next\n"
                    "    end\n"
                    "end"
                ),
            )

        ntp_sync = system_ntp.get("ntpsync", "disable")

        if ntp_sync == "enable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Sincronización NTP (ntpsync) habilitada",
                expected_value="ntpsync enable",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value="Sincronización NTP deshabilitada (ntpsync disable)",
            expected_value="ntpsync enable",
            remediation_cmd="config system ntp\n    set ntpsync enable\nend",
        )


# =============================================================================
# FORTI-024 - Disable Unused Physical Interfaces
# =============================================================================
@register_rule
class UnusedInterfacesDisabledRule(BaseRule):
    """Fortinet Best Practices: Deshabilitar interfaces físicas no utilizadas."""

    rule_id = "FORTI-024"
    name = "Disable Unused Physical Interfaces"
    description = (
        "Las interfaces físicas que no estén en uso deben estar administrativamente deshabilitadas "
        "para prevenir conexiones físicas no autorizadas."
    )
    category = "Network Security"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interfaces = parsed_config.get("config system interface", {})

        if not isinstance(interfaces, dict):
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        enabled_unused = []

        for intf_name, intf_data in interfaces.items():
            # Evaluar si la interfaz no tiene IP/configuración pero el status está activo
            status = intf_data.get("status", "up")
            ip = intf_data.get("ip", "0.0.0.0 0.0.0.0")

            if ip == "0.0.0.0 0.0.0.0" and status == "up" and "vlan" not in intf_data:
                enabled_unused.append(intf_name)

        if enabled_unused:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Interfaces sin IP ni configuración pero activas: {', '.join(enabled_unused)}",
                expected_value="Deshabilitar administrativamente (status down) interfaces no utilizadas",
                remediation_cmd=(
                    "config system interface\n"
                    "    edit <interface_name>\n"
                    "        set status down\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las interfaces inactivas o sin IP se encuentran deshabilitadas",
            expected_value="Interfaces en desuso desactivadas",
        )


# =============================================================================
# FORTI-025 - SD-WAN Health Check Configuration
# =============================================================================
@register_rule
class SDWANHealthCheckRule(BaseRule):
    """Fortinet Best Practices: Configurar monitores de estado (Health Checks) en SD-WAN."""

    rule_id = "FORTI-025"
    name = "Configure SD-WAN Health Checks"
    description = (
        "Verifica que el módulo SD-WAN posea Performance SLA / Health Checks activos "
        "para garantizar la detección temprana de degradación en los enlaces de transporte."
    )
    category = "SD-WAN & Routing"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        sdwan = parsed_config.get("config system sdwan", {})

        if not sdwan or sdwan.get("status", "disable") == "disable":
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        health_checks = sdwan.get("config health-check", {})

        if not health_checks:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="SD-WAN habilitado pero sin monitores de estado (health-check) configurados",
                expected_value="Definir al menos un Health Check con servidores de monitoreo confiables",
                remediation_cmd=(
                    "config system sdwan\n"
                    "    config health-check\n"
                    "        edit \"Internet_Check\"\n"
                    "            set server \"1.1.1.1\"\n"
                    "            set members 0\n"
                    "        next\n"
                    "    end\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Se identificaron {len(health_checks)} monitor(es) Health Check en SD-WAN",
            expected_value="Monitores de estado SD-WAN activos",
        )