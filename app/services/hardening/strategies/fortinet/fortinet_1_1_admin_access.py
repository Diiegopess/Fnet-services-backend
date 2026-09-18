from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# FORTI-001 - Enforce Idle Timeout for Administrators
# =============================================================================
@register_rule
class AdminIdleTimeoutRule(BaseRule):
    """Fortinet Best Practices: Establecer un tiempo de espera de inactividad bajo para administradores."""

    rule_id = "FORTI-001"
    name = "Admin Idle Timeout"
    description = (
        "Configura un tiempo de inactividad de sesión corto para la consola de administración "
        "(preferiblemente menor o igual a 10 minutos) para prevenir accesos no autorizados."
    )
    category = "Management Network"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        # FortiOS almacena admintimeout en minutos. Por defecto suele ser 5 o 15.
        raw_timeout = system_global.get("admintimeout")

        if raw_timeout is None:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Tiempo de inactividad no configurado explícitamente (usando valor por defecto)",
                expected_value="<= 10 minutos",
                remediation_cmd="config system global\n    set admintimeout 10\nend",
            )

        try:
            timeout_val = int(raw_timeout)
        except ValueError:
            timeout_val = 999

        if timeout_val <= 10:
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value=f"Tiempo de espera de inactividad: {timeout_val} minutos",
                expected_value="<= 10 minutos",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value=f"Tiempo de espera actual: {timeout_val} minutos",
            expected_value="<= 10 minutos",
            remediation_cmd="config system global\n    set admintimeout 10\nend",
        )


# =============================================================================
# FORTI-002 - Disable Insecure Management Protocols (HTTP & Telnet)
# =============================================================================
@register_rule
class DisableInsecureProtocolsRule(BaseRule):
    """Fortinet Best Practices: Deshabilitar protocolos inseguros de administración (HTTP y Telnet)."""

    rule_id = "FORTI-002"
    name = "Disable Insecure Management Protocols"
    description = (
        "Garantiza que la administración HTTP y Telnet no estén habilitadas en las interfaces de red "
        "o a nivel global para proteger las credenciales transmitidas en texto claro."
    )
    category = "Management Network"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        # Revisamos la configuración de interfaces
        interfaces = parsed_config.get("config system interface", {})
        open_insecure_interfaces = []

        if isinstance(interfaces, dict):
            for intf_name, intf_data in interfaces.items():
                allowaccess = intf_data.get("allowaccess", "")
                access_list = [acc.strip().lower() for acc in allowaccess.split()]

                if "http" in access_list or "telnet" in access_list:
                    open_insecure_interfaces.append(intf_name)

        if open_insecure_interfaces:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Protocolos inseguros (HTTP/Telnet) permitidos en interfaces: {', '.join(open_insecure_interfaces)}",
                expected_value="HTTP y Telnet totalmente deshabilitados en todas las interfaces",
                remediation_cmd=(
                    "config system interface\n"
                    f"    edit <interface_name>\n"
                    "        set allowaccess https ssh\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="HTTP y Telnet están deshabilitados en todas las interfaces",
            expected_value="Solo protocolos seguros activos (HTTPS / SSH)",
        )


# =============================================================================
# FORTI-003 - Disable HTTP to HTTPS Redirect
# =============================================================================
@register_rule
class DisableHTTPRedirectRule(BaseRule):
    """Fortinet Best Practices: Deshabilitar o asegurar la redirección HTTP a HTTPS."""

    rule_id = "FORTI-003"
    name = "Disable HTTP Redirection"
    description = (
        "Recomienda deshabilitar la redirección automática de HTTP a HTTPS para prevenir el escaneo "
        "y descubrimiento de puertos de administración expuestos."
    )
    category = "Administrative Settings"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        admin_https_redirect = system_global.get("admin-https-redirect", "enable")

        if admin_https_redirect == "disable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Redirección HTTP a HTTPS deshabilitada",
                expected_value="admin-https-redirect disable",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value="Redirección HTTP a HTTPS habilitada (expone servicio HTTP)",
            expected_value="admin-https-redirect disable",
            remediation_cmd="config system global\n    set admin-https-redirect disable\nend",
        )


# =============================================================================
# FORTI-004 - Change Default Admin Username
# =============================================================================
@register_rule
class NonStandardAdminUserRule(BaseRule):
    """Fortinet Best Practices: Renombrar o evitar el uso de la cuenta 'admin' por defecto."""

    rule_id = "FORTI-004"
    name = "Change Default Admin Username"
    description = (
        "El usuario 'admin' es ampliamente conocido y blanco de ataques de fuerza bruta. "
        "Se recomienda crear superusuarios personalizados y deshabilitar o no usar la cuenta 'admin'."
    )
    category = "Administrator Access"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        admins = parsed_config.get("config system admin", {})

        if not admins:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        if "admin" in admins:
            admin_data = admins["admin"]
            status = admin_data.get("status", "enable")

            if status == "enable":
                return RuleResult(
                    status=FindingStatus.FAILED,
                    current_value="La cuenta por defecto 'admin' está activa",
                    expected_value="Usar nombres de usuario administradores personalizados y deshabilitar 'admin'",
                    remediation_cmd=(
                        "config system admin\n"
                        "    edit \"admin\"\n"
                        "        set status disable\n"
                        "    next\n"
                        "end"
                    ),
                )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="La cuenta 'admin' por defecto no existe o está deshabilitada",
            expected_value="Cuenta 'admin' deshabilitada",
        )


    