from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 2.2.1 - Ensure Administrator Password Timeout is Configured
# =============================================================================
@register_rule
class EnsureAdminIdleTimeoutRule(BaseRule):
    """CIS Benchmark 2.2.1: Ensure Administrator Password Timeout is Configured."""

    rule_id = "CIS-2.2.1"
    name = "Ensure Admin Idle Timeout"
    description = (
        "Configura el tiempo máximo de inactividad antes de cerrar la sesión de "
        "administrador para prevenir accesos no autorizados por consolas desatendidas."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        try:
            idle_timeout = int(global_config.get("admintimeout", 5))
        except (ValueError, TypeError):
            idle_timeout = 5

        if idle_timeout < 1 or idle_timeout > 15:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"admintimeout: {idle_timeout} minutos",
                expected_value="admintimeout entre 1 y 15 minutos",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Ajuste el tiempo de inactividad de la sesión de administración (ejemplo: 10 minutos):\n"
                    "     config system global\n"
                    "         set admintimeout 10\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Settings.\n"
                    "   b. Ubique el panel 'Administrator Settings'.\n"
                    "   c. En el campo 'Idle timeout', especifique un valor de minutos entre 1 y 15 (recomendado: 10).\n"
                    "   d. Guarde los cambios haciendo clic en 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Tiempo de inactividad configurado correctamente: {idle_timeout} minutos",
            expected_value="admintimeout entre 1 y 15 minutos",
        )


# =============================================================================
# CIS 2.2.2 - Ensure Administrator Password Policy is Enabled
# =============================================================================
@register_rule
class EnsureAdminPasswordPolicyRule(BaseRule):
    """CIS Benchmark 2.2.2: Ensure Administrator Password Policy is Enabled."""

    rule_id = "CIS-2.2.2"
    name = "Ensure Admin Password Policy"
    description = (
        "Habilita y fuerza la política global de contraseñas para garantizar la "
        "complejidad y longitud mínima de las credenciales locales."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/password-policy"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        pwd_policy = parsed_config.get("config system password-policy") or parsed_config.get("system password-policy") or parsed_config

        status = pwd_policy.get("status", "disable")

        if status != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"password-policy status: {status}",
                expected_value="password-policy status: enable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Active y configure la política estricta de complejidad de contraseñas:\n"
                    "     config system password-policy\n"
                    "         set status enable\n"
                    "         set min-lower-case-letter 1\n"
                    "         set min-upper-case-letter 1\n"
                    "         set min-non-alphanumeric 1\n"
                    "         set min-number 1\n"
                    "         set minimum-length 12\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Navegue a System > Settings.\n"
                    "   b. En la sección 'Password Policy', active el interruptor 'Apply password policy'.\n"
                    "   c. Defina 'Minimum length' en 12 caracteres o superior.\n"
                    "   d. Marque las casillas para requerir mayúsculas, minúsculas, números y caracteres especiales.\n"
                    "   e. Aplique los cambios haciendo clic en 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Política global de contraseñas para administradores habilitada (status: enable)",
            expected_value="password-policy status: enable",
        )


# =============================================================================
# CIS 2.2.3 - Ensure Login Lockout Duration is Configured
# =============================================================================
@register_rule
class EnsureAdminLockoutDurationRule(BaseRule):
    """CIS Benchmark 2.2.3: Ensure Login Lockout Duration is Configured."""

    rule_id = "CIS-2.2.3"
    name = "Ensure Admin Lockout Duration"
    description = (
        "Define la duración del bloqueo de cuenta tras múltiples intentos fallidos "
        "para mitigar ataques de fuerza bruta."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        try:
            lockout_duration = int(global_config.get("admin-lockout-duration", 60))
        except (ValueError, TypeError):
            lockout_duration = 60

        if lockout_duration < 60:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"admin-lockout-duration: {lockout_duration} segundos",
                expected_value="admin-lockout-duration >= 60 segundos",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Aumente el tiempo de bloqueo de cuentas administradoras tras intentos fallidos (mínimo 60 segundos):\n"
                    "     config system global\n"
                    "         set admin-lockout-duration 60\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: El parámetro de duración del bloqueo por intentos fallidos de inicio de sesión "
                    "se gestiona de forma global y exclusiva mediante la CLI para evitar evasiones de fuerza bruta."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Duración de bloqueo configurada: {lockout_duration} segundos",
            expected_value="admin-lockout-duration >= 60 segundos",
        )


# =============================================================================
# CIS 2.2.4 - Ensure Login Lockout Threshold is Configured
# =============================================================================
@register_rule
class EnsureAdminLockoutThresholdRule(BaseRule):
    """CIS Benchmark 2.2.4: Ensure Login Lockout Threshold is Configured."""

    rule_id = "CIS-2.2.4"
    name = "Ensure Admin Lockout Threshold"
    description = (
        "Establece el número máximo de intentos fallidos permitidos antes de "
        "bloquear temporalmente el acceso a la cuenta de administración."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        try:
            lockout_threshold = int(global_config.get("admin-lockout-threshold", 3))
        except (ValueError, TypeError):
            lockout_threshold = 3

        if lockout_threshold < 1 or lockout_threshold > 3:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"admin-lockout-threshold: {lockout_threshold}",
                expected_value="admin-lockout-threshold entre 1 y 3 intentos",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Ajuste el umbral máximo de intentos de inicio de sesión fallidos:\n"
                    "     config system global\n"
                    "         set admin-lockout-threshold 3\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: El umbral de intentos fallidos antes de bloquear una cuenta "
                    "se gestiona exclusivamente desde la línea de comandos (CLI)."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Umbral de bloqueo configurado: {lockout_threshold} intentos",
            expected_value="admin-lockout-threshold entre 1 y 3 intentos",
        )


# =============================================================================
# CIS 2.2.5 - Ensure Two-Factor Authentication is Enabled for Admin Accounts
# =============================================================================
@register_rule
class EnsureAdminMFAEnabledRule(BaseRule):
    """CIS Benchmark 2.2.5: Ensure Two-Factor Authentication is Enabled for Admin Accounts."""

    rule_id = "CIS-2.2.5"
    name = "Ensure Admin Two-Factor Authentication"
    description = (
        "Exige autenticación de dos factores (2FA/MFA) para todas las cuentas "
        "locales de administración."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/admin"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        admin_config = parsed_config.get("config system admin") or parsed_config.get("system admin") or parsed_config

        non_mfa_admins = []

        if isinstance(admin_config, dict):
            # Manejo de la estructura parseada (CLI o dict de API con 'results')
            results = admin_config.get("results", admin_config)
            
            if isinstance(results, list):
                for admin in results:
                    if isinstance(admin, dict):
                        admin_name = admin.get("name", "Unknown")
                        two_factor = admin.get("two-factor", "disable")
                        if two_factor == "disable":
                            non_mfa_admins.append(admin_name)
            elif isinstance(results, dict):
                for admin_name, admin_data in results.items():
                    if isinstance(admin_data, dict):
                        two_factor = admin_data.get("two-factor", "disable")
                        if two_factor == "disable":
                            non_mfa_admins.append(admin_name)

        if non_mfa_admins:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Administradores sin 2FA: {', '.join(non_mfa_admins)}",
                expected_value="Todos los administradores con 'two-factor' habilitado (fortitoken / email / sms)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Habilite 2FA para el administrador deseado:\n"
                    "     config system admin\n"
                    "         edit \"<nombre_admin>\"\n"
                    "             set two-factor fortitoken\n"
                    "             set fortitoken \"<SN_token>\"\n"
                    "         next\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Vaya a System > Administrators.\n"
                    "   b. Edite el usuario correspondiente.\n"
                    "   c. Habilite 'Two-factor Authentication' y seleccione el tipo (FortiToken/Email/SMS).\n"
                    "   d. Guarde haciendo clic en 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todos los usuarios administradores tienen 2FA configurado",
            expected_value="Autenticación de dos factores activa en cuentas administrativas",
        )

from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 2.2.6 - Ensure Admin HTTP Port is Changed
# =============================================================================
@register_rule
class EnsureAdminHTTPPortChangedRule(BaseRule):
    """CIS Benchmark 2.2.6: Ensure Admin HTTP Port is Changed or Disabled."""

    rule_id = "CIS-2.2.6"
    name = "Disable or Change Admin HTTP Port"
    description = (
        "Deshabilita o cambia el puerto HTTP por defecto (puerto 80) para evitar "
        "la transmisión de tráfico administrativo en texto plano."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        admin_port = str(global_config.get("admin-port", "80"))
        admin_https_redirect = global_config.get("admin-https-redirect", "disable")

        if admin_port == "80" and admin_https_redirect != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"admin-port: {admin_port}, admin-https-redirect: {admin_https_redirect}",
                expected_value="admin-port distinto de 80 o admin-https-redirect habilitado",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Fuerce el redireccionamiento de tráfico HTTP hacia HTTPS:\n"
                    "     config system global\n"
                    "         set admin-https-redirect enable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Settings.\n"
                    "   b. En 'Administrator Settings', active la casilla 'Redirect HTTP to HTTPS'.\n"
                    "   c. Guarde los cambios haciendo clic en 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Acceso HTTP seguro mediante redirección HTTPS activa o puerto cambiado",
            expected_value="Tráfico HTTP no seguro bloqueado/redireccionado",
        )


# =============================================================================
# CIS 2.2.7 - Ensure Admin HTTPS Port is Changed from Default
# =============================================================================
@register_rule
class EnsureAdminHTTPSPortChangedRule(BaseRule):
    """CIS Benchmark 2.2.7: Ensure Admin HTTPS Port is Changed from Default."""

    rule_id = "CIS-2.2.7"
    name = "Change Admin HTTPS Port"
    description = (
        "Cambia el puerto por defecto de administración HTTPS (443) para oscurecer "
        "el punto de acceso a la GUI y reducir escaneos automatizados no deseados."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        admin_sport = str(global_config.get("admin-sport", "443"))

        if admin_sport == "443":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"admin-sport: {admin_sport} (Puerto por defecto)",
                expected_value="admin-sport cambiado a un puerto personalizado (ej. 8443)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Cambie el puerto HTTPS administrativo por un puerto no predeterminado (ej. 8443):\n"
                    "     config system global\n"
                    "         set admin-sport 8443\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Settings.\n"
                    "   b. En 'Administrator Settings', cambie el valor de 'HTTPS port' a un puerto personalizado (ej. 8443).\n"
                    "   c. Aplique los cambios haciendo clic en 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Puerto HTTPS de administración personalizado: {admin_sport}",
            expected_value="admin-sport distinto de 443",
        )


# =============================================================================
# CIS 2.2.8 - Ensure Admin SSH Port is Changed from Default
# =============================================================================
@register_rule
class EnsureAdminSSHPortChangedRule(BaseRule):
    """CIS Benchmark 2.2.8: Ensure Admin SSH Port is Changed from Default."""

    rule_id = "CIS-2.2.8"
    name = "Change Admin SSH Port"
    description = (
        "Cambia el puerto estándar de administración SSH (22) para reducir los intentos "
        "de fuerza bruta y escaneos de vulnerabilidades en la consola de comandos."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        admin_ssh_port = str(global_config.get("admin-ssh-port", "22"))

        if admin_ssh_port == "22":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"admin-ssh-port: {admin_ssh_port} (Puerto por defecto)",
                expected_value="admin-ssh-port cambiado a un puerto personalizado (ej. 2222)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Cambie el puerto SSH de administración por un puerto personalizado (ej. 2222):\n"
                    "     config system global\n"
                    "         set admin-ssh-port 2222\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > Settings.\n"
                    "   b. En la sección 'Administrator Settings', busque el campo 'SSH port' y cambie '22' por otro valor (ej. 2222).\n"
                    "   c. Guarde los cambios haciendo clic en 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Puerto SSH de administración personalizado: {admin_ssh_port}",
            expected_value="admin-ssh-port distinto de 22",
        )


# =============================================================================
# CIS 2.2.9 - Ensure SSH v1 is Disabled / CBC Ciphers Disabled
# =============================================================================
@register_rule
class DisableSSHWeakCiphersRule(BaseRule):
    """CIS Benchmark 2.2.9: Ensure SSH CBC ciphers and weak algorithms are disabled."""

    rule_id = "CIS-2.2.9"
    name = "Disable SSH Weak Ciphers"
    description = (
        "Deshabilita los algoritmos de cifrado vulnerables (como CBC) en el servicio "
        "SSH para prevenir ataques de recuperación de texto plano (p. ej. SSH CBC Oracles)."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        ssh_cbc = global_config.get("ssh-cbc-cipher", "enable")
        ssh_hmac_md5 = global_config.get("ssh-hmac-md5", "enable")

        if ssh_cbc != "disable" or ssh_hmac_md5 != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"ssh-cbc-cipher: {ssh_cbc}, ssh-hmac-md5: {ssh_hmac_md5}",
                expected_value="ssh-cbc-cipher: disable y ssh-hmac-md5: disable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Deshabilite los cifrados CBC y algoritmos HMAC débiles en SSH:\n"
                    "     config system global\n"
                    "         set ssh-cbc-cipher disable\n"
                    "         set ssh-hmac-md5 disable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: Las opciones de algoritmos de cifrado para el servicio SSH "
                    "no están expuestas en el portal Web y deben configurarse exclusivamente por la CLI."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Cifrados débiles y HMAC-MD5 deshabilitados en SSH",
            expected_value="ssh-cbc-cipher y ssh-hmac-md5 en disable",
        )


# =============================================================================
# CIS 2.2.10 - Restrict Administrator Access to Specific Trusted Hosts
# =============================================================================
@register_rule
class EnsureAdminTrustedHostsRule(BaseRule):
    """CIS Benchmark 2.2.10: Restrict Administrator Access to Specific Trusted Hosts."""

    rule_id = "CIS-2.2.10"
    name = "Restrict Admin Access to Trusted Hosts"
    description = (
        "Garantiza que las cuentas de administración local tengan restringido el acceso "
        "únicamente a direcciones IP o subredes de confianza (trusthost)."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/admin"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        admin_config = parsed_config.get("config system admin") or parsed_config.get("system admin") or parsed_config

        unrestricted_admins = []

        if isinstance(admin_config, dict):
            results = admin_config.get("results", admin_config)

            if isinstance(results, list):
                for admin in results:
                    if isinstance(admin, dict):
                        admin_name = admin.get("name", "Unknown")
                        has_trusthost = any(key.startswith("trusthost") and value for key, value in admin.items())
                        if not has_trusthost:
                            unrestricted_admins.append(admin_name)
            elif isinstance(results, dict):
                for admin_name, admin_data in results.items():
                    if isinstance(admin_data, dict):
                        has_trusthost = any(key.startswith("trusthost") and value for key, value in admin_data.items())
                        if not has_trusthost:
                            unrestricted_admins.append(admin_name)

        if unrestricted_admins:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Administradores sin restricciones IP (trusthost): {', '.join(unrestricted_admins)}",
                expected_value="Todos los usuarios administradores deben tener al menos un 'trusthost' definido",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Defina al menos una IP o red autorizada para el administrador:\n"
                    "     config system admin\n"
                    "         edit \"<nombre_admin>\"\n"
                    "             set trusthost1 <IP_Gestion>/32\n"
                    "         next\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Diríjase a System > Administrators.\n"
                    "   b. Edite el usuario que requiere la restricción.\n"
                    "   c. Active la opción 'Restrict admin login from trusted hosts only'.\n"
                    "   d. Agregue la IP/Subred permitida en 'Trusted Host 1'.\n"
                    "   e. Guarde los cambios con 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las cuentas administrativas tienen restricciones de trusthost configuradas",
            expected_value="Confianza explícita por IP definida en usuarios administradores",
        )


# =============================================================================
# CIS 2.2.11 - Ensure Administrator Access is Restricted via System Interface
# =============================================================================
@register_rule
class RestrictAdminAccessInterfacesRule(BaseRule):
    """CIS Benchmark 2.2.11: Ensure Administrator Access is Restricted via System Interface."""

    rule_id = "CIS-2.2.11"
    name = "Restrict Management Access on Interfaces"
    description = (
        "Verifica que los protocolos de gestión administrativa (HTTP, HTTPS, SSH, TELNET) "
        "estén deshabilitados en interfaces expuestas a zonas no seguras o WAN."
    )
    category = "Administrator Accounts"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/interface"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interface_config = parsed_config.get("config system interface") or parsed_config.get("system interface") or parsed_config

        exposed_interfaces = []
        unsecure_mgmt = {"http", "telnet"}

        if isinstance(interface_config, dict):
            results = interface_config.get("results", interface_config)

            if isinstance(results, list):
                for iface in results:
                    if isinstance(iface, dict):
                        iface_name = iface.get("name", "Unknown")
                        allowaccess = iface.get("allowaccess", "")
                        access_list = [acc.strip().lower() for acc in allowaccess.split()]
                        found_unsecure = set(access_list).intersection(unsecure_mgmt)
                        if found_unsecure:
                            exposed_interfaces.append(f"{iface_name} ({', '.join(found_unsecure)})")
            elif isinstance(results, dict):
                for iface_name, iface_data in results.items():
                    if isinstance(iface_data, dict):
                        allowaccess = iface_data.get("allowaccess", "")
                        access_list = [acc.strip().lower() for acc in allowaccess.split()]
                        found_unsecure = set(access_list).intersection(unsecure_mgmt)
                        if found_unsecure:
                            exposed_interfaces.append(f"{iface_name} ({', '.join(found_unsecure)})")

        if exposed_interfaces:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Interfaces con gestión insegura permitida: {'; '.join(exposed_interfaces)}",
                expected_value="No permitir HTTP ni TELNET en allowaccess de ninguna interfaz",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Remueva los accesos no seguros (HTTP/TELNET) de la interfaz de red:\n"
                    "     config system interface\n"
                    "         edit \"<nombre_interfaz>\"\n"
                    "             set allowaccess https ssh ping\n"
                    "         next\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Network > Interfaces.\n"
                    "   b. Seleccione la interfaz afectada y haga clic en 'Edit'.\n"
                    "   c. En el apartado 'Administrative Access', desmarque las casillas 'HTTP' y 'TELNET'.\n"
                    "   d. Guarde los cambios haciendo clic en 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Ninguna interfaz tiene activos protocolos inseguros de gestión (HTTP/TELNET)",
            expected_value="HTTP y TELNET deshabilitados en allowaccess de todas las interfaces",
        )