from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 5.1.1 - Ensure Encrypted Logging to FortiAnalyzer/FortiManager
# =============================================================================
@register_rule
class EnsureEncryptedFortiAnalyzerLoggingRule(BaseRule):
    """CIS Benchmark 5.1.1: Ensure Encrypted Logging to FortiAnalyzer/FortiManager."""

    rule_id = "CIS-5.1.1"
    name = "Encrypt FortiAnalyzer/FortiManager Logging"
    description = (
        "Garantiza que el envío de logs hacia FortiAnalyzer o FortiManager utilice "
        "cifrado (SSL/TLS) para proteger la confidencialidad de los eventos de red."
    )
    category = "Logging and Reporting"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        faz_config = parsed_config.get("config log fortianalyzer setting") or parsed_config.get("log fortianalyzer setting", {})

        status = faz_config.get("status", "disable")
        enc_algorithm = faz_config.get("enc-algorithm", "high")

        if status == "enable" and enc_algorithm == "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"enc-algorithm: {enc_algorithm}",
                expected_value="enc-algorithm: high o default (TLS activo)",
                remediation_cmd=(
                    "config log fortianalyzer setting\n"
                    "    set enc-algorithm high\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Cifrado activo en el transporte de logs a FortiAnalyzer",
            expected_value="Cifrado TLS en el envío de logs",
        )


# =============================================================================
# CIS 5.1.2 - Ensure Centralized Syslog Server is Configured
# =============================================================================
@register_rule
class EnsureSyslogConfiguredRule(BaseRule):
    """CIS Benchmark 5.1.2: Ensure Centralized Syslog Server is Configured."""

    rule_id = "CIS-5.1.2"
    name = "Ensure Remote Syslog Logging Configured"
    description = (
        "Verifica que el dispositivo envíe sus registros a un servidor Syslog "
        "remoto/SIEM centralizado para almacenamiento persistente y no repudiación."
    )
    category = "Logging and Reporting"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        syslog_config = parsed_config.get("config log syslogd setting") or parsed_config.get("log syslogd setting", {})
        faz_config = parsed_config.get("config log fortianalyzer setting") or parsed_config.get("log fortianalyzer setting", {})

        syslog_status = syslog_config.get("status", "disable")
        faz_status = faz_config.get("status", "disable")

        # Se requiere al menos un mecanismo de logging externo activo (Syslog o FortiAnalyzer)
        if syslog_status != "enable" and faz_status != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Ni Syslog ni FortiAnalyzer están habilitados",
                expected_value="Al menos un destino de logs remoto activo (Syslog o FortiAnalyzer)",
                remediation_cmd=(
                    "config log syslogd setting\n"
                    "    set status enable\n"
                    "    set server \"<IP_Servidor_Syslog>\"\n"
                    "    set mode reliable # Usar TCP/TLS si está disponible\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Envío de registros remotos centralizado activo",
            expected_value="Syslog o FortiAnalyzer configurado correctamente",
        )


# =============================================================================
# CIS 5.1.3 - Ensure Event Logging is Enabled for All System Events
# =============================================================================
@register_rule
class EnsureEventLoggingEnabledRule(BaseRule):
    """CIS Benchmark 5.1.3: Ensure Event Logging is Enabled for All System Events."""

    rule_id = "CIS-5.1.3"
    name = "Enable Event Logging for System Activity"
    description = (
        "Asegura que el registro de eventos del sistema (cambios de configuración, "
        "autenticación de administradores, estado de interfaces) esté totalmente activo."
    )
    category = "Logging and Reporting"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        event_filter = parsed_config.get("config log eventfilter") or parsed_config.get("log eventfilter", {})

        event_status = event_filter.get("event", "enable")
        system_status = event_filter.get("system", "enable")
        admin_status = event_filter.get("admin", "enable")

        if any(stat == "disable" for stat in [event_status, system_status, admin_status]):
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"event: {event_status}, system: {system_status}, admin: {admin_status}",
                expected_value="Todos los filtros de eventos críticos habilitados",
                remediation_cmd=(
                    "config log eventfilter\n"
                    "    set event enable\n"
                    "    set system enable\n"
                    "    set admin enable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Registro de eventos del sistema y administración completamente activo",
            expected_value="Event logging habilitado",
        )


# =============================================================================
# CIS 5.1.4 - Ensure Disk Log Full Option is Set to Overwrite or Alert
# =============================================================================
@register_rule
class EnsureDiskFullActionRule(BaseRule):
    """CIS Benchmark 5.1.4: Ensure Disk Log Full Action is Configured Correctly."""

    rule_id = "CIS-5.1.4"
    name = "Ensure Disk Full Log Strategy"
    description = (
        "Configura la acción cuando el almacenamiento local de disco se llena "
        "(nolog / overwrite) para evitar la interrupción del servicio o la pérdida no controlada."
    )
    category = "Logging and Reporting"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        disk_setting = parsed_config.get("config log disk setting") or parsed_config.get("log disk setting", {})

        action = disk_setting.get("action", "overwrite")

        if action == "nolog":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"action: {action} (Detiene el registro al llenarse el disco)",
                expected_value="action: overwrite (o reescritura controlada)",
                remediation_cmd=(
                    "config log disk setting\n"
                    "    set action overwrite\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Estrategia ante disco lleno configurada en: {action}",
            expected_value="action: overwrite",
        )

    # =============================================================================
# CIS 5.1.5 - Ensure Log Threat Weight is Configured
# =============================================================================
@register_rule
class EnsureLogThreatWeightRule(BaseRule):
    """CIS Benchmark 5.1.5: Ensure Log Threat Weight is Configured."""

    rule_id = "CIS-5.1.5"
    name = "Ensure Log Threat Weight Active"
    description = (
        "Garantiza que la ponderación de amenazas (Threat Weight) esté configurada "
        "para priorizar y categorizar el riesgo de la red de forma automatizada."
    )
    category = "Logging and Reporting"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        threat_weight = parsed_config.get("config log threat-weight") or parsed_config.get("log threat-weight", {})

        status = threat_weight.get("status", "enable")

        if status == "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"log threat-weight status: {status}",
                expected_value="log threat-weight status: enable",
                remediation_cmd=(
                    "config log threat-weight\n"
                    "    set status enable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Cálculo y asignación de peso a amenazas (Threat Weight) activo",
            expected_value="log threat-weight status: enable",
        )


# =============================================================================
# CIS 5.1.6 - Ensure Memory Logging is Disabled
# =============================================================================
@register_rule
class DisableMemoryLoggingRule(BaseRule):
    """CIS Benchmark 5.1.6: Ensure Memory Logging is Disabled."""

    rule_id = "CIS-5.1.6"
    name = "Disable RAM Memory Logging"
    description = (
        "Deshabilita el almacenamiento de logs en la memoria RAM del equipo "
        "para evitar el consumo excesivo de memoria en producción y pérdida de logs al reiniciar."
    )
    category = "Logging and Reporting"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        memory_setting = parsed_config.get("config log memory setting") or parsed_config.get("log memory setting", {})

        status = memory_setting.get("status", "disable")

        if status == "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"log memory status: {status}",
                expected_value="log memory status: disable",
                remediation_cmd=(
                    "config log memory setting\n"
                    "    set status disable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Almacenamiento de logs en memoria RAM deshabilitado correctamente",
            expected_value="log memory status: disable",
        )


# =============================================================================
# CIS 5.1.7 - Ensure Alert Email Settings are Configured
# =============================================================================
@register_rule
class EnsureAlertEmailConfiguredRule(BaseRule):
    """CIS Benchmark 5.1.7: Ensure Alert Email Settings are Configured."""

    rule_id = "CIS-5.1.7"
    name = "Ensure Alert Email Notifications"
    description = (
        "Verifica que el envío de alertas por correo electrónico ante eventos "
        "críticos de la red o fallos del sistema esté habilitado."
    )
    category = "Logging and Reporting"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        alert_email = parsed_config.get("config alertemail setting") or parsed_config.get("alertemail setting", {})

        mailto = alert_email.get("mailto1")
        status = alert_email.get("username")  # Revisa si hay credenciales/servidor configurado

        if not mailto:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No hay correo de destino configurado para recibir alertas críticos",
                expected_value="mailto1 configurado con una dirección de correo válida para el SOC/Admin",
                remediation_cmd=(
                    "config alertemail setting\n"
                    "    set mailto1 \"soc@empresa.com\"\n"
                    "    set email-interval 5\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Alertas críticas por correo configuradas hacia: {mailto}",
            expected_value="Dirección de correo destinatario de alertas presente",
        )