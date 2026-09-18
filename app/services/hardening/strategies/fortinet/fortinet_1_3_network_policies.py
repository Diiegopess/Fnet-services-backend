from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# FORTI-010 - Firewall Session Handling During Policy/Routing Changes
# =============================================================================
@register_rule
class FirewallSessionDirtyRule(BaseRule):
    """Fortinet Best Practices: Controlar la revalidación de sesiones durante cambios de políticas o rutas."""

    rule_id = "FORTI-010"
    name = "Firewall Session Handling (Session Dirty)"
    description = (
        "Evalúa la configuración de 'firewall-session-dirty'. En entornos de alto tráfico, "
        "revalidar todas las sesiones activas (check-all) puede generar picos de CPU. "
        "Se recomienda ajustar este parámetro según las necesidades de rendimiento vs. seguridad de la organización."
    )
    category = "Day to Day Operations & Policies"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_settings = parsed_config.get("config system settings", {})

        if not system_settings:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        session_dirty = system_settings.get("firewall-session-dirty", "check-all")

        # Se informa la configuración actual para auditoría operacional
        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"firewall-session-dirty está configurado en '{session_dirty}'",
            expected_value="Configurado según el balance requerido (check-all para máxima seguridad, check-new o check-policy-option para optimizar CPU)",
        )


# =============================================================================
# FORTI-011 - Restrict Any/All Objects in Firewall Security Policies
# =============================================================================
@register_rule
class RestrictAnyAllInPoliciesRule(BaseRule):
    """Fortinet Best Practices: Evitar el uso de objetos 'all' o 'any' en políticas de seguridad."""

    rule_id = "FORTI-011"
    name = "Restrict 'all' or 'any' Objects in Security Policies"
    description = (
        "Aplica el principio de menor privilegio evitando el uso indiscriminado de origen o destino 'all'/"
        "'any' en políticas de firewall, excepto cuando se enruta tráfico hacia Internet."
    )
    category = "Network Security Policies"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy", {})

        if not policies:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        overly_permissive_policies = []

        for policy_id, policy_data in policies.items():
            action = policy_data.get("action", "accept")
            if action != "accept":
                continue

            srcaddr = policy_data.get("srcaddr", "")
            dstaddr = policy_data.get("dstaddr", "")

            # Identificar reglas internas que usen 'all' simultáneamente en origen y destino
            if "all" in srcaddr.lower() and "all" in dstaddr.lower():
                overly_permissive_policies.append(str(policy_id))

        if overly_permissive_policies:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas con origen y destino 'all' detectadas (IDs): {', '.join(overly_permissive_policies)}",
                expected_value="Especificar redes, direcciones o usuarios concretos en lugar del objeto 'all'",
                remediation_cmd=(
                    "config firewall policy\n"
                    f"    edit <policy_id>\n"
                    "        set srcaddr <specific_addr_group>\n"
                    "        set dstaddr <specific_addr_group>\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="No se encontraron políticas genéricas 'all' a 'all'",
            expected_value="Uso restringido de objetos 'all'",
        )


# =============================================================================
# FORTI-012 - Enable Match VIP on Deny Policies
# =============================================================================
@register_rule
class MatchVipOnDenyPoliciesRule(BaseRule):
    """Fortinet Best Practices: Habilitar match-vip en políticas de denegación."""

    rule_id = "FORTI-012"
    name = "Enable match-vip on Deny Policies"
    description = (
        "Las políticas que incluyen VIPs tienen prioridad sobre otras políticas. "
        "En políticas con acción 'deny', se debe habilitar 'match-vip' para garantizar que el tráfico bloqueado "
        "hacia una VIP no sea evaluado e ignorado por reglas de denegación generales."
    )
    category = "Network Security Policies"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy", {})

        if not policies:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        non_matching_vip_deny_policies = []

        for policy_id, policy_data in policies.items():
            action = policy_data.get("action", "accept")
            if action == "deny":
                match_vip = policy_data.get("match-vip", "disable")
                if match_vip == "disable":
                    non_matching_vip_deny_policies.append(str(policy_id))

        if non_matching_vip_deny_policies:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas 'deny' sin 'match-vip enable' (IDs): {', '.join(non_matching_vip_deny_policies)}",
                expected_value="match-vip enable en todas las políticas con acción deny",
                remediation_cmd=(
                    "config firewall policy\n"
                    f"    edit <policy_id>\n"
                    "        set match-vip enable\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las políticas de denegación tienen 'match-vip' habilitado",
            expected_value="match-vip enable en políticas deny",
        )


# =============================================================================
# FORTI-013 - Enable DoS Policy Protection
# =============================================================================
@register_rule
class DoSPolicyConfiguredRule(BaseRule):
    """Fortinet Best Practices: Configurar políticas de Denegación de Servicio (DoS)."""

    rule_id = "FORTI-013"
    name = "Configure DoS Security Policies"
    description = (
        "Las políticas DoS se evalúan antes que las políticas de seguridad principales para evitar "
        "que el tráfico malicioso/anómalo agote recursos inspeccionando perfiles de seguridad pesados."
    )
    category = "Denial of Service"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        dos_policies = parsed_config.get("config firewall DoS-policy", {})

        if not dos_policies:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No hay políticas DoS configuradas en el sistema",
                expected_value="Al menos una política DoS activa para mitigar inundaciones y escaneos",
                remediation_cmd=(
                    "config firewall DoS-policy\n"
                    "    edit 1\n"
                    "        set interface <interface_name>\n"
                    "        set srcaddr \"all\"\n"
                    "        set dstaddr \"all\"\n"
                    "        config anomaly\n"
                    "            edit \"tcp_syn_flood\"\n"
                    "                set status enable\n"
                    "                set action block\n"
                    "                set threshold 2000\n"
                    "            next\n"
                    "        end\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Se identificaron {len(dos_policies)} política(s) DoS configurada(s)",
            expected_value="Políticas DoS presentes y habilitadas",
        )


# =============================================================================
# FORTI-014 - Configure Local-In Policies for Management Access
# =============================================================================
@register_rule
class LocalInPolicyConfiguredRule(BaseRule):
    """Fortinet Best Practices: Usar políticas Local-In para restringir el acceso expuesto."""

    rule_id = "FORTI-014"
    name = "Restrict Management via Local-In Policies"
    description = (
        "Las políticas Local-In controlan el tráfico dirigido directamente a las interfaces del FortiGate. "
        "Se recomiendan para restringir el acceso a los puertos de administración desde IPs o geografías no autorizadas."
    )
    category = "Hardening & Local-In"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        local_in = parsed_config.get("config firewall local-in-policy", {})

        if not local_in:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No hay políticas local-in configuradas explícitamente",
                expected_value="Políticas local-in definidas para bloquear o restringir el tráfico entrante al plano de control",
                remediation_cmd=(
                    "config firewall local-in-policy\n"
                    "    edit 1\n"
                    "        set intf <wan_interface>\n"
                    "        set srcaddr <trusted_hosts>\n"
                    "        set dstaddr \"ALL\"\n"
                    "        set service \"HTTPS\" \"SSH\"\n"
                    "        set action accept\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Se identificaron {len(local_in)} regla(s) local-in-policy explícita(s)",
            expected_value="Políticas local-in activas para protección del plano de control",
        )