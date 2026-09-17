from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule

# =============================================================================
# CIS 6.1.1 - Ensure HA Cluster Encrypted/Password Authentication is Configured
# =============================================================================
@register_rule
class EnsureHASyncPasswordRule(BaseRule):
    """CIS Benchmark 6.1.1: Ensure HA Cluster Has Sync Password Configured."""

    rule_id = "CIS-6.1.1"
    name = "Ensure HA Cluster Password Protection"
    description = (
        "Garantiza que la sincronización en clúster (High Availability) esté protegida "
        "con una contraseña robusta para evitar la integración no autorizada de nodos al clúster."
    )
    category = "High Availability & VPN"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        ha_config = parsed_config.get("config system ha") or parsed_config.get("system ha", {})
        
        mode = ha_config.get("mode", "standalone")

        if mode == "standalone":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="El equipo no está en modo Alta Disponibilidad (standalone)",
                expected_value="Modo HA no activo o contraseña de HA configurada",
            )

        password = ha_config.get("password")

        if not password:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Clúster HA activo sin contraseña de sincronización definida",
                expected_value="password configurada en 'config system ha'",
                remediation_cmd=(
                    "config system ha\n"
                    "    set password <CONTRASEÑA_ROBUSTA_HA>\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Clúster HA protegido mediante contraseña de autenticación",
            expected_value="password en 'config system ha' configurada",
        )


# =============================================================================
# CIS 6.2.1 - Ensure SSL-VPN Restricts Insecure TLS Versions (TLS 1.2+ Only)
# =============================================================================
@register_rule
class EnsureSSLVPNMinTLSVersionRule(BaseRule):
    """CIS Benchmark 6.2.1: Ensure SSL-VPN Uses Minimum TLS 1.2."""

    rule_id = "CIS-6.2.1"
    name = "Enforce Minimum TLS 1.2 on SSL-VPN"
    description = (
        "Asegura que el servicio SSL-VPN rechace conexiones con versiones obsoletas de TLS "
        "(TLS 1.0 y TLS 1.1) para proteger la transmisión de credenciales y datos."
    )
    category = "High Availability & VPN"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        ssl_vpn = parsed_config.get("config vpn ssl settings") or parsed_config.get("vpn ssl settings", {})
        
        status = ssl_vpn.get("status", "enable")

        if status == "disable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Servicio SSL-VPN totalmente deshabilitado",
                expected_value="SSL-VPN deshabilitado o con TLS 1.2+ como mínimo",
            )

        tls_min = ssl_vpn.get("ssl-min-proto-version", "tls1.2")

        if tls_min in ["tls1.0", "tls1.1"]:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"ssl-min-proto-version: {tls_min}",
                expected_value="ssl-min-proto-version: tls1.2 o tls1.3",
                remediation_cmd=(
                    "config vpn ssl settings\n"
                    "    set ssl-min-proto-version tls1.2\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Versión mínima de protocolo SSL-VPN configurada en: {tls_min}",
            expected_value="ssl-min-proto-version en tls1.2 o superior",
        )


# =============================================================================
# CIS 6.2.2 - Ensure Weak Ciphers (DES/3DES/MD5) are Disabled in IPsec Phase 1
# =============================================================================
@register_rule
class DisableWeakIPsecCiphersRule(BaseRule):
    """CIS Benchmark 6.2.2: Ensure Weak Ciphers are Disabled in IPsec VPNs."""

    rule_id = "CIS-6.2.2"
    name = "Disable Weak Ciphers in IPsec Phase 1"
    description = (
        "Verifica que las fases 1 de las VPN IPsec deshabiliten cifrados o firmas vulnerables "
        "como DES, 3DES o algoritmos de hashing tipo MD5."
    )
    category = "High Availability & VPN"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        phase1_configs = parsed_config.get("config vpn ipsec phase1-interface") or parsed_config.get("vpn ipsec phase1-interface", {})

        insecure_tunnels = []
        weak_crypto = {"des", "3des", "md5"}

        if isinstance(phase1_configs, dict):
            for tunnel_name, tunnel_data in phase1_configs.items():
                if isinstance(tunnel_data, dict):
                    proposal = str(tunnel_data.get("proposal", "")).lower().split()
                    
                    found_weak = set(proposal).intersection(weak_crypto)
                    if found_weak:
                        insecure_tunnels.append(f"{tunnel_name} ({', '.join(found_weak)})")

        if insecure_tunnels:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Túneles IPsec utilizando algoritmos débiles: {'; '.join(insecure_tunnels)}",
                expected_value="Utilizar propuestas de cifrado seguras en Fase 1 (ej. aes256-sha256)",
                remediation_cmd=(
                    "config vpn ipsec phase1-interface\n"
                    "    edit \"<nombre_tunel>\"\n"
                    "        set proposal aes256-sha256 aes128-sha256\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="No se detectaron algoritmos débiles (DES/3DES/MD5) en túneles IPsec",
            expected_value="Propuestas de cifrado robustas en IPsec Phase 1",
        )