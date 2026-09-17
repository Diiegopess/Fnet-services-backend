from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 1.1 - Ensure DNS server is configured
# =============================================================================
@register_rule
class EnsureDNSConfiguredRule(BaseRule):
    """CIS Benchmark 1.1: Ensure DNS server is configured."""

    rule_id = "CIS-1.1"
    name = "Ensure DNS Server Configured"
    description = (
        "Garantiza que el firewall tenga configurados servidores DNS de confianza "
        "para evitar ataques de tipo Man-in-the-Middle y garantizar la resolución correcta de nombres."
    )
    category = "Network Settings"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        dns_config = parsed_config.get("config system dns") or parsed_config.get("system dns")

        if not dns_config:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No se encontró el bloque de configuración 'config system dns'",
                expected_value="Servidor primario y secundario de DNS configurados",
                remediation_cmd=(
                    "config system dns\n"
                    "    set primary 8.8.8.8\n"
                    "    set secondary 8.8.4.4\n"
                    "end"
                ),
            )

        primary = dns_config.get("primary")
        secondary = dns_config.get("secondary")

        # Valores por defecto de Fortinet que no se consideran recomendados si están sin modificar
        default_ips = ("96.45.45.45", "96.45.46.46")

        if not primary or primary in default_ips:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Primary DNS: {primary or 'No definido'} (En uso valores por defecto o no configurado)",
                expected_value="Servidor DNS primario personalizado y confiable",
                remediation_cmd=(
                    "config system dns\n"
                    "    set primary <ip_servidor_dns_primario>\n"
                    "    set secondary <ip_servidor_dns_secundario>\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Primary DNS: {primary}, Secondary DNS: {secondary or 'No definido'}",
            expected_value="Servidores DNS primario y secundario configurados correctamente",
        )


# =============================================================================
# CIS 1.2 - Ensure intra-zone traffic is not always allowed
# =============================================================================
@register_rule
class EnsureIntraZoneTrafficBlockedRule(BaseRule):
    """CIS Benchmark 1.2: Ensure intra-zone traffic is not always allowed."""

    rule_id = "CIS-1.2"
    name = "Block Intra-Zone Traffic"
    description = "Garantiza que el tráfico dentro de la misma zona esté bloqueado de forma predeterminada para evitar desplazamiento lateral no autorizado."
    category = "Network Settings"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        zones = parsed_config.get("config system zone") or parsed_config.get("system zone")

        if not zones:
            return RuleResult(
                status=FindingStatus.NOT_APPLICABLE,
                current_value="No hay zonas configuradas en el sistema",
                expected_value="Zonas con intrazone deny",
            )

        # Si 'zones' es un diccionario de zonas individuales (por ej. dict de edits)
        zones_failing = []

        if isinstance(zones, dict):
            for zone_name, zone_data in zones.items():
                if isinstance(zone_data, dict):
                    intrazone = zone_data.get("intrazone", "allow")  # Por defecto en CLI a veces permite si no se explicita
                    if intrazone != "deny":
                        zones_failing.append(zone_name)

        if zones_failing:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Zonas permitiendo tráfico intra-zona: {', '.join(zones_failing)}",
                expected_value="Todas las zonas deben tener 'set intrazone deny'",
                remediation_cmd="\n".join([
                    f"config system zone\n    edit \"{z}\"\n        set intrazone deny\n    next\nend"
                    for z in zones_failing
                ]),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las zonas tienen el tráfico intra-zona denegado (intrazone deny)",
            expected_value="intrazone deny en todas las zonas",
        )


# =============================================================================
# CIS 1.3 - Disable all management related services on WAN port
# =============================================================================
@register_rule
class DisableManagementOnWANRule(BaseRule):
    """CIS Benchmark 1.3: Disable all management related services on WAN port."""

    rule_id = "CIS-1.3"
    name = "Disable Management Services on WAN"
    description = (
        "Garantiza que los servicios de gestión administrativa (HTTPS, HTTP, PING, SSH, SNMP, RADIUS) "
        "estén deshabilitados en las interfaces expuestas a la WAN para reducir la superficie de ataque."
    )
    category = "Network Settings"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    # Servicios administrativos de riesgo que NO deberían estar en la WAN
    RESTRICTED_SERVICES = {"https", "http", "ping", "ssh", "snmp", "radius-acct"}

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interfaces = parsed_config.get("config system interface") or parsed_config.get("system interface")

        if not interfaces or not isinstance(interfaces, dict):
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        wan_violations = {}

        for iface_name, iface_data in interfaces.items():
            if not isinstance(iface_data, dict):
                continue

            # Detectar si la interfaz es WAN (por nombre común o por alias/rol)
            role = iface_data.get("role", "")
            alias = iface_data.get("alias", "").lower()
            name_lower = iface_name.lower()

            is_wan = role == "wan" or "wan" in name_lower or "wan" in alias or name_lower in ("port1", "outside")

            if is_wan:
                allowaccess = iface_data.get("allowaccess", "")
                
                # allowaccess puede venir como string ("ping https ssh") o como lista/set
                if isinstance(allowaccess, str):
                    enabled_services = set(allowaccess.lower().split())
                elif isinstance(allowaccess, (list, tuple, set)):
                    enabled_services = {s.lower() for s in allowaccess}
                else:
                    enabled_services = set()

                forbidden_active = enabled_services.intersection(self.RESTRICTED_SERVICES)

                if forbidden_active:
                    wan_violations[iface_name] = list(forbidden_active)

        if wan_violations:
            details = [f"{iface}: {', '.join(svcs)}" for iface, svcs in wan_violations.items()]
            remediation_cmds = []
            for iface, svcs in wan_violations.items():
                remediation_cmds.append(
                    f"config system interface\n    edit \"{iface}\"\n        unselect allowaccess {' '.join(svcs)}\n    next\nend"
                )

            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Servicios inseguros activos en WAN -> {'; '.join(details)}",
                expected_value="Ningún servicio administrativo de gestión activo en interfaz WAN",
                remediation_cmd="\n".join(remediation_cmds),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Interfaces WAN no tienen servicios administrativos expuestos",
            expected_value="Gestión deshabilitada en interfaces WAN",
        )