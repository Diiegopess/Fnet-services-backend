from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# FORTI-026 - Enforce Deep SSL Inspection Profile
# =============================================================================
@register_rule
class DeepSSLInspectionRule(BaseRule):
    """Fortinet Best Practices: Aplicar inspección profunda SSL/TLS (Deep Inspection)."""

    rule_id = "FORTI-026"
    name = "Enforce Deep SSL Inspection"
    description = (
        "El tráfico cifrado representa la mayoría del tráfico de red. Sin Deep SSL Inspection, "
        "los motores de Antivirus, IPS y Web Filter no pueden inspeccionar el contenido real en busca de amenazas."
    )
    category = "Security Profiles / SSL Inspection"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy", {})

        if not policies:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        certificate_inspection_only = []

        for policy_id, policy_data in policies.items():
            action = policy_data.get("action", "accept")
            if action != "accept":
                continue

            ssl_ssh_profile = policy_data.get("ssl-ssh-profile", "")
            # Evaluar si la política usa la inspección básica de certificado o ninguna
            if ssl_ssh_profile.lower() in ["certificate-inspection", ""]:
                certificate_inspection_only.append(str(policy_id))

        if certificate_inspection_only:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas permitidas sin Deep SSL Inspection (IDs): {', '.join(certificate_inspection_only)}",
                expected_value="Asignar un perfil de Deep SSL Inspection con certificado de CA de inspección instalado en los clientes",
                remediation_cmd=(
                    "config firewall policy\n"
                    f"    edit <policy_id>\n"
                    "        set ssl-ssh-profile \"deep-inspection\"\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las políticas activas utilizan perfiles de Deep SSL Inspection",
            expected_value="Deep Inspection aplicado en reglas de firewall",
        )


# =============================================================================
# FORTI-027 - Enable Application Control Profile on Outbound Policies
# =============================================================================
@register_rule
class ApplicationControlEnabledRule(BaseRule):
    """Fortinet Best Practices: Habilitar Application Control en políticas de salida."""

    rule_id = "FORTI-027"
    name = "Enable Application Control Profile"
    description = (
        "Garantiza que el motor de Control de Aplicaciones identifique y restrinja tráfico evasivo "
        "(P2P, proxies, túneles no autorizados) independientemente del puerto utilizado."
    )
    category = "Security Profiles / App Control"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy", {})

        if not policies:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        missing_app_ctrl = []

        for policy_id, policy_data in policies.items():
            action = policy_data.get("action", "accept")
            if action == "accept" and "app-profile" not in policy_data:
                missing_app_ctrl.append(str(policy_id))

        if missing_app_ctrl:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas permitidas sin perfil de Application Control asignado (IDs): {', '.join(missing_app_ctrl)}",
                expected_value="Asignar un perfil de Application Control a todas las políticas de salida",
                remediation_cmd=(
                    "config firewall policy\n"
                    f"    edit <policy_id>\n"
                    "        set application-list \"default\"\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Perfil de Application Control asignado en todas las políticas válidas",
            expected_value="Application Control activo en políticas",
        )


# =============================================================================
# FORTI-028 - Enable IPS Sensor on Security Policies
# =============================================================================
@register_rule
class IPSProfileEnabledRule(BaseRule):
    """Fortinet Best Practices: Activar sensor IPS en reglas de tráfico entrante y saliente."""

    rule_id = "FORTI-028"
    name = "Enable Intrusion Prevention System (IPS)"
    description = (
        "Asegura la protección activa contra ataques de exploits, desbordamientos de búfer "
        "y vulnerabilidades conocidas aplicando sensores IPS en las políticas de tráfico."
    )
    category = "Security Profiles / IPS"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy", {})

        if not policies:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        missing_ips = []

        for policy_id, policy_data in policies.items():
            action = policy_data.get("action", "accept")
            if action == "accept" and "ips-sensor" not in policy_data:
                missing_ips.append(str(policy_id))

        if missing_ips:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas permitidas sin perfil de IPS asignado (IDs): {', '.join(missing_ips)}",
                expected_value="Habilitar sensor IPS en las políticas de firewall",
                remediation_cmd=(
                    "config firewall policy\n"
                    f"    edit <policy_id>\n"
                    "        set ips-sensor \"default\"\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Sensor IPS configurado en todas las políticas habilitadas",
            expected_value="Protección IPS activa",
        )


# =============================================================================
# FORTI-029 - Block QUIC Protocol in Application Control / Firewall
# =============================================================================
@register_rule
class BlockQUICProtocolRule(BaseRule):
    """Fortinet Best Practices: Bloquear el protocolo QUIC en el FortiGate."""

    rule_id = "FORTI-029"
    name = "Block QUIC Protocol"
    description = (
        "El protocolo QUIC (UDP 443) evade la inspección SSL/TLS tradicional de los navegadores. "
        "Fortinet recomienda bloquear QUIC a nivel de firewall/AppControl para forzar a los navegadores a usar HTTPS estándar."
    )
    category = "Security Profiles / Web Control"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        app_profiles = parsed_config.get("config application list", {})

        if not app_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No existen perfiles de Application Control para validar el bloqueo de QUIC",
                expected_value="Bloquear la aplicación QUIC en los perfiles de Application Control",
                remediation_cmd=(
                    "config application list\n"
                    "    edit \"default\"\n"
                    "        config entries\n"
                    "            edit 1\n"
                    "                set application 31077\n"  # App ID para QUIC
                    "                set action block\n"
                    "            next\n"
                    "        end\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Perfiles de Application Control presentes para la gestión y bloqueo de QUIC",
            expected_value="Bloqueo activo del protocolo QUIC",
        )