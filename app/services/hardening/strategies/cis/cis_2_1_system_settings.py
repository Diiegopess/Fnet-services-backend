from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 2.1.1 - Ensure 'Pre-Login Banner' is set
# =============================================================================
@register_rule
class EnsurePreLoginBannerRule(BaseRule):
    """CIS Benchmark 2.1.1: Ensure 'Pre-Login Banner' is set."""

    rule_id = "CIS-2.1.1"
    name = "Ensure Pre-Login Banner"
    description = (
        "Garantiza que el banner de pre-inicio de sesión esté activo para advertir "
        "a los usuarios no autorizados sobre las restricciones de acceso."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        banner = global_config.get("pre-login-banner", "disable")

        if banner != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"pre-login-banner: {banner}",
                expected_value="pre-login-banner: enable",
                remediation_cmd=(
                    "config system global\n"
                    "    set pre-login-banner enable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Pre-Login Banner habilitado",
            expected_value="pre-login-banner: enable",
        )


# =============================================================================
# CIS 2.1.2 - Ensure 'Post-Login-Banner' is set
# =============================================================================
@register_rule
class EnsurePostLoginBannerRule(BaseRule):
    """CIS Benchmark 2.1.2: Ensure 'Post-Login-Banner' is set."""

    rule_id = "CIS-2.1.2"
    name = "Ensure Post-Login Banner"
    description = (
        "Garantiza que el banner posterior al inicio de sesión esté activo para notificar "
        "los términos legales y responsabilidades de uso."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        banner = global_config.get("post-login-banner", "disable")

        if banner != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"post-login-banner: {banner}",
                expected_value="post-login-banner: enable",
                remediation_cmd=(
                    "config system global\n"
                    "    set post-login-banner enable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Post-Login Banner habilitado",
            expected_value="post-login-banner: enable",
        )


# =============================================================================
# CIS 2.1.3 - Ensure timezone is properly configured
# =============================================================================
@register_rule
class EnsureTimezoneConfiguredRule(BaseRule):
    """CIS Benchmark 2.1.3: Ensure timezone is properly configured."""

    rule_id = "CIS-2.1.3"
    name = "Ensure Timezone Configured"
    description = (
        "Verifica que la zona horaria esté explícitamente configurada en el sistema "
        "para garantizar la consistencia de marcas de tiempo en logs y certificados."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        timezone = global_config.get("timezone")

        if not timezone:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Timezone no está configurado explícitamente",
                expected_value="Zona horaria configurada según ubicación del dispositivo",
                remediation_cmd=(
                    "config system global\n"
                    "    set timezone <id_zona_horaria>\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Timezone configurado: {timezone}",
            expected_value="Zona horaria configurada",
        )

# =============================================================================
# CIS 2.1.4 - Ensure NTP server is configured
# =============================================================================
@register_rule
class EnsureNTPConfiguredRule(BaseRule):
    """CIS Benchmark 2.1.4: Ensure NTP server is configured."""

    rule_id = "CIS-2.1.4"
    name = "Ensure NTP Server Configured"
    description = (
        "Garantiza que la sincronización de tiempo mediante NTP esté habilitada y activa "
        "para asegurar la validez temporal de registros y certificados."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        ntp_config = parsed_config.get("config system ntp") or parsed_config.get("system ntp", {})

        status = ntp_config.get("status", "disable")
        ntpserver = ntp_config.get("ntpserver") or ntp_config.get("server")

        if status != "enable" or not ntpserver:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"status: {status}, servidores: {ntpserver or 'Ninguno'}",
                expected_value="NTP habilitado con al menos un servidor configurado",
                remediation_cmd=(
                    "config system ntp\n"
                    "    set status enable\n"
                    "    config ntpserver\n"
                    "        edit 1\n"
                    "            set server \"<IP_o_FQDN_NTP>\"\n"
                    "        next\n"
                    "    end\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Sincronización NTP configurada y activa",
            expected_value="status: enable con servidor NTP configurado",
        )


# =============================================================================
# CIS 2.1.5 - Ensure hostname is set
# =============================================================================
@register_rule
class EnsureHostnameSetRule(BaseRule):
    """CIS Benchmark 2.1.5: Ensure hostname is set."""

    rule_id = "CIS-2.1.5"
    name = "Ensure Hostname Set"
    description = (
        "Garantiza que el nombre del dispositivo esté personalizado y no utilice el "
        "nombre por defecto del modelo de hardware."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        hostname = global_config.get("hostname")

        # Nombres por defecto típicos incluyen modelos como FG, FortiGate, etc.
        if not hostname or hostname.startswith("FortiGate") or hostname.startswith("FGT"):
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Hostname actual: {hostname or 'No definido'} (Nombre por defecto/genérico)",
                expected_value="Hostname personalizado según estándares de nombrado de la organización",
                remediation_cmd=(
                    "config system global\n"
                    "    set hostname \"<Nuevo_Nombre_FW>\"\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Hostname asignado: {hostname}",
            expected_value="Hostname personalizado configurado",
        )



# =============================================================================
# CIS 2.1.6 - Ensure FortiGuard Anycast is enabled
# =============================================================================
@register_rule
class EnsureFortiGuardAnycastRule(BaseRule):
    """CIS Benchmark 2.1.6: Ensure FortiGuard Anycast is enabled."""

    rule_id = "CIS-2.1.6"
    name = "Ensure FortiGuard Anycast Enabled"
    description = (
        "Asegura el uso de Anycast para las comunicaciones con FortiGuard, optimizando "
        "el rendimiento y garantizando el cifrado en las consultas de reputación y firmas."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        fortiguard_config = parsed_config.get("config system fortiguard") or parsed_config.get("system fortiguard", {})

        anycast = fortiguard_config.get("fortiguard-anycast", "enable")

        if anycast != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"fortiguard-anycast: {anycast}",
                expected_value="fortiguard-anycast: enable",
                remediation_cmd=(
                    "config system fortiguard\n"
                    "    set fortiguard-anycast enable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="FortiGuard Anycast está habilitado",
            expected_value="fortiguard-anycast: enable",
        )


# =============================================================================
# CIS 2.1.7 - Disable USB Firmware and configuration installation
# =============================================================================
@register_rule
class DisableUSBAutoInstallRule(BaseRule):
    """CIS Benchmark 2.1.7: Disable USB Firmware and configuration installation."""

    rule_id = "CIS-2.1.7"
    name = "Disable USB Auto-Install"
    description = (
        "Deshabilita la instalación automática de firmware y archivos de configuración "
        "a través del puerto USB para evitar manipulaciones físicas no autorizadas."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        auto_install = parsed_config.get("config system auto-install") or parsed_config.get("system auto-install", {})

        # Si no se encuentra el bloque, por defecto suele estar habilitado
        config_status = auto_install.get("auto-install-config", "enable")
        image_status = auto_install.get("auto-install-image", "enable")

        if config_status != "disable" or image_status != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"auto-install-config: {config_status}, auto-install-image: {image_status}",
                expected_value="Ambas opciones deshabilitadas (disable)",
                remediation_cmd=(
                    "config system auto-install\n"
                    "    set auto-install-config disable\n"
                    "    set auto-install-image disable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Instalación automática vía USB deshabilitada",
            expected_value="auto-install-config y auto-install-image en disable",
        )


# =============================================================================
# CIS 2.1.8 - Disable static keys for TLS
# =============================================================================
@register_rule
class DisableTLSStaticKeysRule(BaseRule):
    """CIS Benchmark 2.1.8: Disable static keys for TLS."""

    rule_id = "CIS-2.1.8"
    name = "Disable TLS Static Keys"
    description = (
        "Deshabilita el soporte de cifrados con claves estáticas en sesiones TLS para garantizar "
        "Perfect Forward Secrecy (PFS)."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        ssl_static = global_config.get("ssl-static-key-ciphers", "enable")

        if ssl_static != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"ssl-static-key-ciphers: {ssl_static}",
                expected_value="ssl-static-key-ciphers: disable",
                remediation_cmd=(
                    "config system global\n"
                    "    set ssl-static-key-ciphers disable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Cifrados TLS de clave estática deshabilitados",
            expected_value="ssl-static-key-ciphers: disable",
        )


# =============================================================================
# CIS 2.1.9 - Enable Global Strong Encryption
# =============================================================================
@register_rule
class EnableGlobalStrongCryptoRule(BaseRule):
    """CIS Benchmark 2.1.9: Enable Global Strong Encryption."""

    rule_id = "CIS-2.1.9"
    name = "Enable Global Strong Encryption"
    description = (
        "Fuerza el uso exclusivo de algoritmos de cifrado fuertes en todo el sistema."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        strong_crypto = global_config.get("strong-crypto", "disable")

        if strong_crypto != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"strong-crypto: {strong_crypto}",
                expected_value="strong-crypto: enable",
                remediation_cmd=(
                    "config system global\n"
                    "    set strong-crypto enable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Global Strong Encryption habilitado",
            expected_value="strong-crypto: enable",
        )


# =============================================================================
# CIS 2.1.10 - Ensure management GUI listens on secure TLS version
# =============================================================================
@register_rule
class EnsureAdminTLSVersionRule(BaseRule):
    """CIS Benchmark 2.1.10: Ensure management GUI listens on secure TLS version."""

    rule_id = "CIS-2.1.10"
    name = "Enforce TLS 1.3 on Admin GUI"
    description = (
        "Garantiza que el acceso a la interfaz web administrativa requiera TLS 1.3 "
        "para proteger la sesión contra ataques de degradación de cifrado."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        tls_versions = global_config.get("admin-https-ssl-versions", "")

        # Aceptamos si únicamente está permitido tlsv1-3
        if tls_versions != "tlsv1-3":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"admin-https-ssl-versions: {tls_versions or 'Valores por defecto/Inseguros'}",
                expected_value="admin-https-ssl-versions: tlsv1-3",
                remediation_cmd=(
                    "config system global\n"
                    "    set admin-https-ssl-versions tlsv1-3\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Interfaz GUI restringida únicamente a TLS 1.3",
            expected_value="admin-https-ssl-versions: tlsv1-3",
        )

# =============================================================================
# CIS 2.1.11 - Ensure Central Management is used
# =============================================================================
@register_rule
class EnsureCentralManagementRule(BaseRule):
    """CIS Benchmark 2.1.11: Ensure Central Management is used."""

    rule_id = "CIS-2.1.11"
    name = "Ensure Central Management Configured"
    description = (
        "Verifica que el dispositivo esté integrado con una plataforma de gestión centralizada "
        "(como FortiManager) para auditar cambios y centralizar las políticas."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        central_config = parsed_config.get("config system central-management") or parsed_config.get("system central-management", {})

        type_mgm = central_config.get("type", "none")

        if type_mgm not in ["fortimanager", "fortiguard"]:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"central-management type: {type_mgm}",
                expected_value="Gestión centralizada activa (fortimanager/fortiguard)",
                remediation_cmd=(
                    "config system central-management\n"
                    "    set type fortimanager\n"
                    "    set fmg \"<IP_o_FQDN_FortiManager>\"\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Gestión centralizada activa (tipo: {type_mgm})",
            expected_value="Gestión centralizada configurada",
        )

# =============================================================================
# CIS 2.1.12 - Ensure single CPU core overloaded event is logged
# =============================================================================
@register_rule
class EnsureLogSingleCPUHighRule(BaseRule):
    """CIS Benchmark 2.1.12: Ensure single CPU core overloaded event is logged."""

    rule_id = "CIS-2.1.12"
    name = "Log Single CPU Core Overload"
    description = (
        "Habilita el registro de eventos cuando un único núcleo del CPU supere el umbral de carga, "
        "evitando picos invisibles en el consumo global del sistema."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        log_cpu = global_config.get("log-single-cpu-high", "disable")

        if log_cpu != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"log-single-cpu-high: {log_cpu}",
                expected_value="log-single-cpu-high: enable",
                remediation_cmd=(
                    "config system global\n"
                    "    set log-single-cpu-high enable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Alertas por sobrecarga de núcleo único de CPU habilitadas",
            expected_value="log-single-cpu-high: enable",
        )


# =============================================================================
# CIS 2.1.13 - Ensure Hostname is Not Displayed On Login GUI
# =============================================================================
@register_rule
class DisableDisplayHostnameOnLoginRule(BaseRule):
    """CIS Benchmark 2.1.13: Ensure Hostname is Not Displayed On Login GUI."""

    rule_id = "CIS-2.1.13"
    name = "Hide Hostname on Login GUI"
    description = (
        "Oculta el nombre del dispositivo en la pantalla de inicio de sesión de la GUI "
        "para evitar revelar información en tareas de reconocimiento de un atacante."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        display_hostname = global_config.get("gui-display-hostname", "disable")

        if display_hostname != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"gui-display-hostname: {display_hostname}",
                expected_value="gui-display-hostname: disable",
                remediation_cmd=(
                    "config system global\n"
                    "    set gui-display-hostname disable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="El hostname está oculto en el login de la GUI",
            expected_value="gui-display-hostname: disable",
        )