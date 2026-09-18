from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# FORTI-015 - Enforce Two-Factor Authentication (2FA/MFA) for SSL VPN
# =============================================================================
@register_rule
class SSLVPNTwoFactorAuthRule(BaseRule):
    """Fortinet Best Practices: Exigir autenticación de doble factor en SSL-VPN."""

    rule_id = "FORTI-015"
    name = "Enforce 2FA/MFA for SSL VPN Users"
    description = (
        "Requiere que todos los usuarios o grupos que accedan vía SSL-VPN tengan habilitada "
        "la autenticación de dos factores (FortiToken, SAML/MFA, o TOTP) para mitigar el robo de credenciales."
    )
    category = "Remote Access / SSL VPN"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        ssl_vpn_settings = parsed_config.get("config vpn ssl settings", {})

        if not ssl_vpn_settings:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        users = parsed_config.get("config user local", {})
        users_without_2fa = []

        if isinstance(users, dict):
            for user_name, user_data in users.items():
                two_factor = user_data.get("two-factor", "disable")
                if two_factor == "disable":
                    users_without_2fa.append(user_name)

        if users_without_2fa:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Usuarios locales sin 2FA habilitado: {', '.join(users_without_2fa)}",
                expected_value="Todos los usuarios con acceso a SSL-VPN deben utilizar autenticación de doble factor (two-factor fortitoken/email/sms/saml)",
                remediation_cmd=(
                    "config user local\n"
                    f"    edit <username>\n"
                    "        set two-factor fortitoken\n"
                    "        set fortitoken <token_sn>\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todos los usuarios locales configurados poseen doble factor de autenticación habilitado",
            expected_value="2FA habilitado en cuentas locales",
        )


# =============================================================================
# FORTI-016 - Restrict TLS Versions and Ciphers for SSL VPN
# =============================================================================
@register_rule
class SSLVPNRestrictTLSRule(BaseRule):
    """Fortinet Best Practices: Restringir versiones de TLS en SSL-VPN a TLS 1.2 o superior."""

    rule_id = "FORTI-016"
    name = "Enforce TLS 1.2+ for SSL VPN"
    description = (
        "Deshabilita versiones obsoletas de TLS (TLS 1.0 y 1.1) en el portal de SSL-VPN "
        "para garantizar la integridad y confidencialidad del tráfico de los usuarios remotos."
    )
    category = "Remote Access / SSL VPN"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        ssl_vpn_settings = parsed_config.get("config vpn ssl settings", {})

        if not ssl_vpn_settings:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        min_tls = ssl_vpn_settings.get("ssl-min-proto-version", "tls1-2")

        if min_tls in ["tls1-2", "tls1-3"]:
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value=f"Versión mínima de TLS para SSL-VPN: {min_tls}",
                expected_value="ssl-min-proto-version tls1-2 o superior",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value=f"Versión mínima de TLS insegura permitida: {min_tls}",
            expected_value="ssl-min-proto-version tls1-2",
            remediation_cmd=(
                "config vpn ssl settings\n"
                "    set ssl-min-proto-version tls1-2\n"
                "end"
            ),
        )


# =============================================================================
# FORTI-017 - Restrict IPsec Phase 1 Proposal (Disable Weak Ciphers)
# =============================================================================
@register_rule
class IPsecPhase1EncryptionRule(BaseRule):
    """Fortinet Best Practices: Deshabilitar cifrados débiles en IPsec Fase 1 (DES, 3DES, MD5)."""

    rule_id = "FORTI-017"
    name = "Secure IPsec Phase 1 Proposals"
    description = (
        "Asegura que los túneles IPsec no utilicen algoritmos de cifrado o autenticación desactualizados "
        "como DES, 3DES o MD5 en la Fase 1."
    )
    category = "Remote Access / IPsec VPN"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        phase1_configs = parsed_config.get("config vpn ipsec phase1-interface", {})

        if not phase1_configs:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        weak_tunnels = []

        for tunnel_name, tunnel_data in phase1_configs.items():
            proposal = tunnel_data.get("proposal", "").lower()
            if "des" in proposal or "3des" in proposal or "md5" in proposal:
                weak_tunnels.append(tunnel_name)

        if weak_tunnels:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Túneles IPsec Fase 1 utilizando algoritmos débiles (DES/3DES/MD5): {', '.join(weak_tunnels)}",
                expected_value="Usar unicamente AES128, AES256 o superior con SHA256 o superior",
                remediation_cmd=(
                    "config vpn ipsec phase1-interface\n"
                    "    edit <tunnel_name>\n"
                    "        set proposal aes256-sha256 aes128-sha256\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las fases 1 de IPsec utilizan algoritmos de cifrado y autenticación seguros",
            expected_value="Propuestas IPsec Fase 1 seguras",
        )


# =============================================================================
# FORTI-018 - Enable High Availability Monitored Interfaces
# =============================================================================
@register_rule
class HAMonitoredInterfacesRule(BaseRule):
    """Fortinet Best Practices: Configurar interfaces monitoreadas en clústeres HA."""

    rule_id = "FORTI-018"
    name = "HA Monitored Interfaces Configured"
    description = (
        "Garantiza que el clúster de Alta Disponibilidad tenga configurado el monitoreo de interfaces claves (monitor). "
        "De lo contrario, la caída de un enlace físico no provocará el conmutado (failover) del nodo."
    )
    category = "High Availability"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        ha_config = parsed_config.get("config system ha", {})

        if not ha_config:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        mode = ha_config.get("mode", "standalone")
        if mode == "standalone":
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        monitor = ha_config.get("monitor", "")

        if not monitor:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Clúster HA activo pero sin interfaces monitoreadas (monitor desconfigurado)",
                expected_value="Configurar 'monitor' apuntando a las interfaces críticas de datos/WAN",
                remediation_cmd=(
                    "config system ha\n"
                    "    set monitor \"port1\" \"port2\"\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Interfaces monitoreadas en HA: {monitor}",
            expected_value="Interfaces de monitoreo de HA configuradas",
        )