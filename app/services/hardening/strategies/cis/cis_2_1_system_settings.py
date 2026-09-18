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
        "a los usuarios no autorizados sobre las restricciones de acceso antes del inicio de sesión."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        banner = global_config.get("pre-login-banner", "disable")

        if banner != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"pre-login-banner: {banner}",
                expected_value="pre-login-banner: enable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Ejecute el siguiente comando para activar el banner de pre-inicio de sesión:\n"
                    "     config system global\n"
                    "         set pre-login-banner enable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Replacement Messages.\n"
                    "   b. En el panel de la derecha, ubique la sección 'Administrator'.\n"
                    "   c. Seleccione 'Pre-login Disclaimer' y haga clic en 'Edit'.\n"
                    "   d. Modifique el mensaje institucional según los requisitos de su organización.\n"
                    "   e. Asegúrese de guardar los cambios haciendo clic en 'Save'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Pre-Login Banner habilitado (pre-login-banner: enable)",
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
        "los términos legales y responsabilidades de uso una vez autenticado el usuario."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        banner = global_config.get("post-login-banner", "disable")

        if banner != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"post-login-banner: {banner}",
                expected_value="post-login-banner: enable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Ejecute el siguiente comando para activar el banner posterior al inicio de sesión:\n"
                    "     config system global\n"
                    "         set post-login-banner enable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Replacement Messages.\n"
                    "   b. En el panel de la derecha, ubique la sección 'Administrator'.\n"
                    "   c. Seleccione 'Post-login Disclaimer' y haga clic en 'Edit'.\n"
                    "   d. Personalice la declaración o términos legales de la organización.\n"
                    "   e. Guarde los cambios haciendo clic en 'Save'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Post-Login Banner habilitado (post-login-banner: enable)",
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
        "para garantizar la consistencia de marcas de tiempo en auditorías, logs y certificados."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        timezone = global_config.get("timezone")

        if not timezone:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Timezone no está configurado explícitamente",
                expected_value="Zona horaria configurada explícitamente según la ubicación del dispositivo",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Ajuste la zona horaria definiendo el código numérico correspondiente (ejemplo: 12 para UTC-5):\n"
                    "     config system global\n"
                    "         set timezone <id_zona_horaria>\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Navegue a System > Settings.\n"
                    "   b. Ubique el panel 'System Time'.\n"
                    "   c. En el menú desplegable 'Time Zone', seleccione la zona horaria correspondiente a la ubicación del equipo.\n"
                    "   d. Haga clic en 'Apply' en la parte inferior para guardar los cambios."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Timezone configurado explícitamente: {timezone}",
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/ntp"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        ntp_config = parsed_config.get("config system ntp") or parsed_config.get("system ntp") or parsed_config

        status = ntp_config.get("status", "disable")
        ntpserver = ntp_config.get("ntpserver") or ntp_config.get("server")

        if status != "enable" or not ntpserver:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"status: {status}, servidores: {ntpserver or 'Ninguno'}",
                expected_value="NTP habilitado con al menos un servidor configurado",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Ejecute los siguientes comandos para habilitar NTP y registrar un servidor confiable:\n"
                    "     config system ntp\n"
                    "         set status enable\n"
                    "         config ntpserver\n"
                    "             edit 1\n"
                    "                 set server \"<IP_o_FQDN_NTP>\"\n"
                    "             next\n"
                    "         end\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Navegue a System > Settings.\n"
                    "   b. Ubique la sección 'System Time'.\n"
                    "   c. En 'NTP Server', seleccione 'Specify' (o asegúrese de activar la sincronización NTP).\n"
                    "   d. Ingrese la dirección IP o FQDN de su servidor NTP en el campo 'Server'.\n"
                    "   e. Haga clic en 'Apply' para guardar la configuración."
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
        "nombre por defecto del modelo de hardware para facilitar el monitoreo y auditorías."
    )
    category = "System Settings"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        hostname = global_config.get("hostname")

        if not hostname or hostname.startswith("FortiGate") or hostname.startswith("FGT"):
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Hostname actual: {hostname or 'No definido'} (Nombre por defecto/genérico)",
                expected_value="Hostname personalizado según estándares de nombrado de la organización",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Ejecute el siguiente comando para asignar el nombre corporativo:\n"
                    "     config system global\n"
                    "         set hostname \"<Nuevo_Nombre_FW>\"\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Settings.\n"
                    "   b. En el panel 'System Information', ubique el campo 'Host Name'.\n"
                    "   c. Escriba el nombre asignado para el dispositivo.\n"
                    "   d. Haga clic en 'Apply' al final de la página."
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/fortiguard"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        fortiguard_config = parsed_config.get("config system fortiguard") or parsed_config.get("system fortiguard") or parsed_config

        anycast = fortiguard_config.get("fortiguard-anycast", "enable")

        if anycast != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"fortiguard-anycast: {anycast}",
                expected_value="fortiguard-anycast: enable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Habilite Anycast para los servicios de FortiGuard ejecutando:\n"
                    "     config system fortiguard\n"
                    "         set fortiguard-anycast enable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Navegue a System > FortiGuard.\n"
                    "   b. En la sección 'FortiGuard Join/Connection Options', habilite 'Use FortiGuard Anycast'.\n"
                    "   c. Guarde los cambios haciendo clic en 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="FortiGuard Anycast está habilitado (fortiguard-anycast: enable)",
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/auto-install"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        auto_install = parsed_config.get("config system auto-install") or parsed_config.get("system auto-install") or parsed_config

        config_status = auto_install.get("auto-install-config", "enable")
        image_status = auto_install.get("auto-install-image", "enable")

        if config_status != "disable" or image_status != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"auto-install-config: {config_status}, auto-install-image: {image_status}",
                expected_value="Ambas opciones deshabilitadas (disable)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Deshabilite la auto-instalación desde USB ejecutando:\n"
                    "     config system auto-install\n"
                    "         set auto-install-config disable\n"
                    "         set auto-install-image disable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: Esta configuración se gestiona de manera global y exclusiva a través de la CLI "
                    "para prevenir la carga accidental de scripts o firmware desde dispositivos de almacenamiento USB masivo."
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        ssl_static = global_config.get("ssl-static-key-ciphers", "enable")

        if ssl_static != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"ssl-static-key-ciphers: {ssl_static}",
                expected_value="ssl-static-key-ciphers: disable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Deshabilite el uso de claves estáticas SSL/TLS ejecutando:\n"
                    "     config system global\n"
                    "         set ssl-static-key-ciphers disable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: Esta propiedad de robustez criptográfica avanzada global "
                    "no expone conmutador directo en la interfaz gráfica y debe gestionarse por CLI."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Cifrados TLS de clave estática deshabilitados (ssl-static-key-ciphers: disable)",
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        strong_crypto = global_config.get("strong-crypto", "disable")

        if strong_crypto != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"strong-crypto: {strong_crypto}",
                expected_value="strong-crypto: enable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Habilite el cifrado fuerte global mediante los comandos:\n"
                    "     config system global\n"
                    "         set strong-crypto enable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: El parámetro 'strong-crypto' desactiva globalmente algoritmos débiles "
                    "(como DES, 3DES, MD5 o ciphers < 128-bit). Debe aplicarse mediante la CLI "
                    "para garantizar que no interfiera con túneles VPN heredados existentes."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Global Strong Encryption habilitado (strong-crypto: enable)",
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        tls_versions = global_config.get("admin-https-ssl-versions", "")

        if tls_versions != "tlsv1-3":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"admin-https-ssl-versions: {tls_versions or 'Valores por defecto/Inseguros'}",
                expected_value="admin-https-ssl-versions: tlsv1-3",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Restrinja las conexiones de administración web exclusivamente a TLS 1.3:\n"
                    "     config system global\n"
                    "         set admin-https-ssl-versions tlsv1-3\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Navegue a System > Settings.\n"
                    "   b. Ubique la sección 'Administrator Settings'.\n"
                    "   c. En el campo 'HTTPS Server TLS Version', seleccione únicamente 'TLS 1.3'.\n"
                    "   d. Guarde los cambios haciendo clic en 'Apply'."
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/central-management"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        central_config = parsed_config.get("config system central-management") or parsed_config.get("system central-management") or parsed_config

        type_mgm = central_config.get("type", "none")

        if type_mgm not in ["fortimanager", "fortiguard"]:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"central-management type: {type_mgm}",
                expected_value="Gestión centralizada activa (fortimanager/fortiguard)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Configure la asociación con la IP/FQDN de FortiManager:\n"
                    "     config system central-management\n"
                    "         set type fortimanager\n"
                    "         set fmg \"<IP_o_FQDN_FortiManager>\"\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Vaya a Security Fabric > Central Management.\n"
                    "   b. En 'Central Management Status', active la opción e introduzca la IP de su servidor FortiManager.\n"
                    "   c. Haga clic en 'Apply' y acepte la solicitud de registro desde la consola de FortiManager."
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        log_cpu = global_config.get("log-single-cpu-high", "disable")

        if log_cpu != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"log-single-cpu-high: {log_cpu}",
                expected_value="log-single-cpu-high: enable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Active la generación de logs de eventos para núcleos individuales saturados:\n"
                    "     config system global\n"
                    "         set log-single-cpu-high enable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: Este ajuste de telemetría de rendimiento a nivel de hardware/kernel "
                    "se habilita exclusivamente mediante la línea de comandos (CLI)."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Alertas por sobrecarga de núcleo único de CPU habilitadas (log-single-cpu-high: enable)",
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

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        display_hostname = global_config.get("gui-display-hostname", "disable")

        if display_hostname != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"gui-display-hostname: {display_hostname}",
                expected_value="gui-display-hostname: disable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Oculte el Hostname de la pantalla de bienvenida enviando:\n"
                    "     config system global\n"
                    "         set gui-display-hostname disable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Settings.\n"
                    "   b. En la sección 'View Settings' o 'Administrator Settings', busque 'Display Hostname on Login Page'.\n"
                    "   c. Desmarque la casilla para deshabilitarlo.\n"
                    "   d. Guarde los cambios haciendo clic en 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="El hostname está oculto en el login de la GUI (gui-display-hostname: disable)",
            expected_value="gui-display-hostname: disable",
        )