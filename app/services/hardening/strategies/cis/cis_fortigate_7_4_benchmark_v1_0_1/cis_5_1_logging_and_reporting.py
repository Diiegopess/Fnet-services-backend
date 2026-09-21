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

    required_endpoint = "api/v2/cmdb/log.fortianalyzer/setting"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        faz_config = (
            parsed_config.get("config log fortianalyzer setting")
            or parsed_config.get("log fortianalyzer setting")
            or parsed_config
        )

        status = "disable"
        enc_algorithm = "high"

        if isinstance(faz_config, dict):
            results = faz_config.get("results", faz_config)

            if isinstance(results, list) and len(results) > 0:
                first_item = results[0]
                if isinstance(first_item, dict):
                    status = str(first_item.get("status", "disable")).lower()
                    enc_algorithm = str(first_item.get("enc-algorithm", "high")).lower()
            elif isinstance(results, dict):
                status = str(results.get("status", "disable")).lower()
                enc_algorithm = str(results.get("enc-algorithm", "high")).lower()

        if status == "enable" and enc_algorithm == "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"enc-algorithm: {enc_algorithm}",
                expected_value="enc-algorithm: high o default (TLS activo)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Habilite el cifrado de transmisión de logs hacia FortiAnalyzer:\n"
                    "     config log fortianalyzer setting\n"
                    "         set enc-algorithm high\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Fabric > Fabric Connectors.\n"
                    "   b. Edite la integración con 'FortiAnalyzer'.\n"
                    "   c. Asegúrese de mantener activa la conexión cifrada (Encrypt log transmission / SSL/TLS).\n"
                    "   d. Guarde los cambios haciendo clic en 'OK'."
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

    # Endpoint principal evaluado
    required_endpoint = "api/v2/cmdb/log.syslogd/setting"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        syslog_config = (
            parsed_config.get("config log syslogd setting")
            or parsed_config.get("log syslogd setting")
            or parsed_config.get("syslogd", {})
            or parsed_config
        )
        faz_config = (
            parsed_config.get("config log fortianalyzer setting")
            or parsed_config.get("log fortianalyzer setting")
            or parsed_config.get("fortianalyzer", {})
        )

        syslog_status = "disable"
        faz_status = "disable"

        # Extraer estado de Syslog
        if isinstance(syslog_config, dict):
            results_syslog = syslog_config.get("results", syslog_config)
            if isinstance(results_syslog, list) and len(results_syslog) > 0:
                item = results_syslog[0]
                if isinstance(item, dict):
                    syslog_status = str(item.get("status", "disable")).lower()
            elif isinstance(results_syslog, dict):
                syslog_status = str(results_syslog.get("status", "disable")).lower()

        # Extraer estado de FortiAnalyzer
        if isinstance(faz_config, dict):
            results_faz = faz_config.get("results", faz_config)
            if isinstance(results_faz, list) and len(results_faz) > 0:
                item = results_faz[0]
                if isinstance(item, dict):
                    faz_status = str(item.get("status", "disable")).lower()
            elif isinstance(results_faz, dict):
                faz_status = str(results_faz.get("status", "disable")).lower()

        if syslog_status != "enable" and faz_status != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Ni Syslog ni FortiAnalyzer están habilitados",
                expected_value="Al menos un destino de logs remoto activo (Syslog o FortiAnalyzer)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Configure el servicio de Syslog remoto:\n"
                    "     config log syslogd setting\n"
                    "         set status enable\n"
                    "         set server \"<IP_Servidor_Syslog>\"\n"
                    "         set mode reliable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Log & Report > Log Settings.\n"
                    "   b. En la sección 'Remote Logging', habilite 'Send Logs to Syslog'.\n"
                    "   c. Ingrese la dirección IP del servidor Syslog/SIEM y defina el modo de transporte (TCP/Reliable recommended).\n"
                    "   d. Guarde los cambios mediante 'Apply'."
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

    required_endpoint = "api/v2/cmdb/log/eventfilter"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        event_filter = (
            parsed_config.get("config log eventfilter")
            or parsed_config.get("log eventfilter")
            or parsed_config
        )

        event_status = "enable"
        system_status = "enable"
        admin_status = "enable"

        if isinstance(event_filter, dict):
            results = event_filter.get("results", event_filter)

            if isinstance(results, list) and len(results) > 0:
                first_item = results[0]
                if isinstance(first_item, dict):
                    event_status = str(first_item.get("event", "enable")).lower()
                    system_status = str(first_item.get("system", "enable")).lower()
                    admin_status = str(first_item.get("admin", "enable")).lower()
            elif isinstance(results, dict):
                event_status = str(results.get("event", "enable")).lower()
                system_status = str(results.get("system", "enable")).lower()
                admin_status = str(results.get("admin", "enable")).lower()

        if any(stat == "disable" for stat in [event_status, system_status, admin_status]):
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"event: {event_status}, system: {system_status}, admin: {admin_status}",
                expected_value="Todos los filtros de eventos críticos habilitados",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Habilite el registro de eventos del sistema y administración:\n"
                    "     config log eventfilter\n"
                    "         set event enable\n"
                    "         set system enable\n"
                    "         set admin enable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Log & Report > Log Settings.\n"
                    "   b. En la sección 'Event Logging', asegúrese de marcar la casilla 'Enable All' o seleccionar individualmente 'System', 'Admin', y 'Event'.\n"
                    "   c. Guarde los cambios con 'Apply'."
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

    required_endpoint = "api/v2/cmdb/log.disk/setting"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        disk_setting = (
            parsed_config.get("config log disk setting")
            or parsed_config.get("log disk setting")
            or parsed_config
        )

        action = "overwrite"

        if isinstance(disk_setting, dict):
            results = disk_setting.get("results", disk_setting)

            if isinstance(results, list) and len(results) > 0:
                first_item = results[0]
                if isinstance(first_item, dict):
                    action = str(first_item.get("action", "overwrite")).lower()
            elif isinstance(results, dict):
                action = str(results.get("action", "overwrite")).lower()

        if action == "nolog":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"action: {action} (Detiene el registro al llenarse el disco)",
                expected_value="action: overwrite (o reescritura controlada)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config log disk setting\n"
                    "       set action overwrite\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Log & Report > Log Settings.\n"
                    "   b. En la sección 'Local Logging' (si está disponible según el modelo de hardware), busque la opción 'Disk Full Action'.\n"
                    "   c. Seleccione 'Overwrite oldest logs' en lugar de 'Do not log'.\n"
                    "   d. Guarde los cambios mediante 'Apply'."
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

    required_endpoint = "api/v2/cmdb/log/threat-weight"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        threat_weight = (
            parsed_config.get("config log threat-weight")
            or parsed_config.get("log threat-weight")
            or parsed_config
        )

        status = "enable"

        if isinstance(threat_weight, dict):
            results = threat_weight.get("results", threat_weight)

            if isinstance(results, list) and len(results) > 0:
                first_item = results[0]
                if isinstance(first_item, dict):
                    status = str(first_item.get("status", "enable")).lower()
            elif isinstance(results, dict):
                status = str(results.get("status", "enable")).lower()

        if status == "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"log threat-weight status: {status}",
                expected_value="log threat-weight status: enable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config log threat-weight\n"
                    "       set status enable\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Fabric > Global Settings (o Log & Report > Threat Weight).\n"
                    "   b. Habilite el cálculo de 'Threat Weight'.\n"
                    "   c. Guarde la configuración."
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

    required_endpoint = "api/v2/cmdb/log.memory/setting"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        memory_setting = (
            parsed_config.get("config log memory setting")
            or parsed_config.get("log memory setting")
            or parsed_config
        )

        status = "disable"

        if isinstance(memory_setting, dict):
            results = memory_setting.get("results", memory_setting)

            if isinstance(results, list) and len(results) > 0:
                first_item = results[0]
                if isinstance(first_item, dict):
                    status = str(first_item.get("status", "disable")).lower()
            elif isinstance(results, dict):
                status = str(results.get("status", "disable")).lower()

        if status == "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"log memory status: {status}",
                expected_value="log memory status: disable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config log memory setting\n"
                    "       set status disable\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Log & Report > Log Settings.\n"
                    "   b. En la sección de destinos de almacenamiento, deshabilite 'Enable Memory Logging' / 'Log to RAM'.\n"
                    "   c. Haga clic en 'Apply' para guardar."
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

    required_endpoint = "api/v2/cmdb/alertemail/setting"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        alert_email = (
            parsed_config.get("config alertemail setting")
            or parsed_config.get("alertemail setting")
            or parsed_config
        )

        mailto = None

        if isinstance(alert_email, dict):
            results = alert_email.get("results", alert_email)

            if isinstance(results, list) and len(results) > 0:
                first_item = results[0]
                if isinstance(first_item, dict):
                    mailto = first_item.get("mailto1") or first_item.get("mailto2") or first_item.get("mailto3")
            elif isinstance(results, dict):
                mailto = results.get("mailto1") or results.get("mailto2") or results.get("mailto3")

        if not mailto:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No hay correo de destino configurado para recibir alertas críticas",
                expected_value="mailto1 configurado con una dirección de correo válida para el SOC/Admin",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config alertemail setting\n"
                    "       set mailto1 \"soc@empresa.com\"\n"
                    "       set email-interval 5\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Advanced / Automation.\n"
                    "   b. Configure los parámetros del servidor SMTP e ingrese la dirección del destinatario (Mail To).\n"
                    "   c. Guarde la configuración."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Alertas críticas por correo configuradas hacia: {mailto}",
            expected_value="Dirección de correo destinatario de alertas presente",
        )