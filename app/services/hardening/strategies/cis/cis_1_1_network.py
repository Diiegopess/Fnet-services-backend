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
        "Garantiza que el firewall tenga configurados servidores DNS corporativos o de confianza "
        "para evitar ataques de tipo Man-in-the-Middle y garantizar la resolución correcta de nombres."
    )
    category = "Network Settings"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    required_endpoint = "api/v2/cmdb/system/dns"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        dns_config = parsed_config.get("config system dns") or parsed_config.get("system dns") or parsed_config

        if not dns_config:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No se encontró la configuración del servidor DNS",
                expected_value="Servidores DNS primarios y secundarios configurados y personalizados",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "     config system dns\n"
                    "         set primary 8.8.8.8\n"
                    "         set secondary 8.8.4.4\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Navegue a Network > DNS.\n"
                    "   b. Seleccione la opción 'Specify'.\n"
                    "   c. Ingrese la dirección IP en 'Primary DNS Server' y 'Secondary DNS Server'.\n"
                    "   d. Haga clic en 'Apply' para guardar los cambios."
                ),
            )

        primary = dns_config.get("primary")
        secondary = dns_config.get("secondary")
        default_ips = ("96.45.45.45", "96.45.46.46")

        if not primary or primary in default_ips:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Primary DNS: {primary or 'No definido'} (Usa valores por defecto o sin configurar)",
                expected_value="Servidor DNS primario personalizado y confiable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "     config system dns\n"
                    "         set primary <ip_servidor_dns_primario>\n"
                    "         set secondary <ip_servidor_dns_secundario>\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Network > DNS.\n"
                    "   b. Cambie la opción a 'Specify' e ingrese sus servidores DNS.\n"
                    "   c. Guarde los cambios haciendo clic en 'Apply'."
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
    description = (
        "Garantiza que el tráfico entre interfaces de la misma zona esté bloqueado por defecto "
        "para evitar el desplazamiento lateral no autorizado entre segmentos de red."
    )
    category = "Network Settings"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    required_endpoint = "api/v2/cmdb/system/zone"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        endpoint_response = (
            parsed_config.get(self.required_endpoint)
            or parsed_config.get(f"/{self.required_endpoint}")
        )

        if endpoint_response is not None:
            if isinstance(endpoint_response, dict):
                zones = endpoint_response.get("results", endpoint_response)
            else:
                zones = endpoint_response
        else:
            # Compatibilidad con configuraciones estáticas usadas por pruebas antiguas.
            zones = parsed_config.get("config system zone") or parsed_config.get("system zone") or parsed_config

        if not zones:
            return RuleResult(
                status=FindingStatus.NOT_APPLICABLE,
                current_value="No hay zonas configuradas en el sistema",
                expected_value="Zonas con parámetro 'intrazone deny'",
            )

        zones_failing = []

        if isinstance(zones, list):
            for index, zone_data in enumerate(zones):
                if isinstance(zone_data, dict):
                    zone_name = (
                        zone_data.get("name")
                        or zone_data.get("id")
                        or zone_data.get("q_origin_key")
                        or f"zone-{index + 1}"
                    )
                    intrazone = zone_data.get("intrazone", "allow")
                    if intrazone != "deny":
                        zones_failing.append(str(zone_name))
        elif isinstance(zones, dict):
            for zone_name, zone_data in zones.items():
                if isinstance(zone_data, dict):
                    intrazone = zone_data.get("intrazone", "allow")
                    if intrazone != "deny":
                        zones_failing.append(zone_name)

        if zones_failing:
            failing_list_str = ", ".join(zones_failing)
            cli_commands = "\n".join([
                f"   config system zone\n       edit \"{z}\"\n           set intrazone deny\n       next\n   end"
                for z in zones_failing
            ])

            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Zonas permitiendo tráfico intra-zona: {failing_list_str}",
                expected_value="Todas las zonas deben tener configurado 'set intrazone deny'",
                remediation_cmd=(
                    f"PASOS DE REMEDIACIÓN:\n\n"
                    f"Se identificaron las siguientes zonas no conformes: {failing_list_str}\n\n"
                    f"1. A través de la CLI de FortiGate:\n\n"
                    f"{cli_commands}\n\n"
                    f"2. A través de la Interfaz Gráfica (GUI):\n"
                    f"   a. Ingrese a Network > Interfaces.\n"
                    f"   b. Seleccione la zona afectada y haga clic en 'Edit'.\n"
                    f"   c. Active la casilla 'Block intra-zone traffic'.\n"
                    f"   d. Guarde los cambios con el botón 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las zonas tienen el tráfico intra-zona denegado (intrazone deny)",
            expected_value="intrazone deny activo en todas las zonas configuradas",
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
        "Garantiza que los servicios de gestión administrativa (HTTPS, HTTP, PING, SSH, SNMP, RADIUS-ACCT) "
        "estén totalmente deshabilitados en las interfaces expuestas a la WAN para reducir la superficie de ataque."
    )
    category = "Network Settings"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    required_endpoint = "api/v2/cmdb/system/interface"

    RESTRICTED_SERVICES = {"https", "http", "ping", "ssh", "snmp", "radius-acct"}

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interfaces = parsed_config.get("config system interface") or parsed_config.get("system interface") or parsed_config

        if not interfaces or not isinstance(interfaces, dict):
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        wan_violations = {}

        for iface_name, iface_data in interfaces.items():
            if not isinstance(iface_data, dict):
                continue

            role = iface_data.get("role", "")
            alias = iface_data.get("alias", "").lower()
            name_lower = iface_name.lower()

            is_wan = role == "wan" or "wan" in name_lower or "wan" in alias or name_lower in ("port1", "outside")

            if is_wan:
                allowaccess = iface_data.get("allowaccess", "")

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
            
            cli_remediations = []
            gui_remediations = []

            for iface, svcs in wan_violations.items():
                svcs_str = " ".join(svcs)
                cli_remediations.append(
                    f"   config system interface\n       edit \"{iface}\"\n           unselect allowaccess {svcs_str}\n       next\n   end"
                )
                gui_remediations.append(
                    f"   - Interfaz '{iface}': Desmarque las casillas {', '.join(svcs).upper()} en 'Administrative Access'."
                )

            cli_str = "\n".join(cli_remediations)
            gui_str = "\n".join(gui_remediations)

            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Servicios de administración expuestos en WAN -> {'; '.join(details)}",
                expected_value="Ningún servicio administrativo activo en interfaces expuestas a la WAN",
                remediation_cmd=(
                    f"PASOS DE REMEDIACIÓN:\n\n"
                    f"1. A través de la CLI de FortiGate:\n\n"
                    f"{cli_str}\n\n"
                    f"2. A través de la Interfaz Gráfica (GUI):\n"
                    f"   a. Ingrese a Network > Interfaces.\n"
                    f"   b. Identifique y edite la interfaz WAN correspondiente.\n"
                    f"   c. En la sección 'Administrative Access', deshabilite los servicios administrativos no permitidos:\n"
                    f"{gui_str}\n"
                    f"   d. Guarde los cambios haciendo clic en 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Las interfaces WAN no tienen servicios administrativos expuestos",
            expected_value="Gestión administrativa deshabilitada en interfaces WAN",
        )