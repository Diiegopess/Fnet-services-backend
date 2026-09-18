from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 4.1.1 - Ensure AntiVirus Profile is Enabled and Configured
# =============================================================================
@register_rule
class EnsureAntivirusProfileConfiguredRule(BaseRule):
    """CIS Benchmark 4.1.1: Ensure AntiVirus Profile is Enabled and Configured."""

    rule_id = "CIS-4.1.1"
    name = "Ensure AntiVirus Profile Configured"
    description = (
        "Garantiza que los perfiles de Antivirus escaneen protocolos clave (HTTP, FTP, SMTP, IMAP, POP3) "
        "y utilicen la base de datos de firmas extendida o de aprendizaje profundo (FortiSandbox/AI)."
    )
    category = "Security Profiles"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    required_endpoint = "api/v2/cmdb/antivirus/profile"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        av_profiles = (
            parsed_config.get("config antivirus profile")
            or parsed_config.get("antivirus profile")
            or parsed_config
        )

        insecure_profiles = []
        has_profiles = False

        if isinstance(av_profiles, dict):
            results = av_profiles.get("results", av_profiles)

            if isinstance(results, list):
                if results:
                    has_profiles = True
                for profile in results:
                    if isinstance(profile, dict):
                        prof_name = profile.get("name", profile.get("q_origin_key", "desconocido"))
                        http_config = profile.get("http", {})
                        http_options = http_config.get("options", "") if isinstance(http_config, dict) else str(http_config)
                        
                        if "scan" not in str(http_options):
                            insecure_profiles.append(prof_name)

            elif isinstance(results, dict):
                if results:
                    has_profiles = True
                for profile_name, profile_data in results.items():
                    if isinstance(profile_data, dict):
                        http_config = profile_data.get("http", {})
                        http_options = http_config.get("options", "") if isinstance(http_config, dict) else str(http_config)
                        
                        if "scan" not in str(http_options):
                            insecure_profiles.append(profile_name)

        if not has_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No hay perfiles de Antivirus configurados",
                expected_value="Al menos un perfil de Antivirus activo con escaneo en protocolos principales",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config antivirus profile\n"
                    "       edit \"default\"\n"
                    "           config http\n"
                    "               set options scan\n"
                    "           end\n"
                    "       next\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Profiles > AntiVirus.\n"
                    "   b. Edite el perfil predeterminado o cree uno nuevo.\n"
                    "   c. En HTTP/HTTPS y otros protocolos requeridos, asegúrese de activar la opción 'Scan'.\n"
                    "   d. Guarde los cambios con 'Apply'."
                ),
            )

        if insecure_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Perfiles de Antivirus sin escaneo HTTP activo: {', '.join(insecure_profiles)}",
                expected_value="Escaneo HTTP (scan) activo en los perfiles Antivirus",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config antivirus profile\n"
                    "       edit \"<nombre_perfil>\"\n"
                    "           config http\n"
                    "               set options scan\n"
                    "           end\n"
                    "       next\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Profiles > AntiVirus.\n"
                    "   b. Seleccione el perfil afectado y haga clic en 'Edit'.\n"
                    "   c. Active la inspección y escaneo en las opciones del protocolo HTTP.\n"
                    "   d. Guarde los cambios."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Perfiles de Antivirus configurados con inspección activa en tráfico web",
            expected_value="Perfiles Antivirus con análisis HTTP activo",
        )


# =============================================================================
# CIS 4.1.2 - Ensure Web Filter Profile Blocks Malicious Categories
# =============================================================================
@register_rule
class EnsureWebFilterCategoriesRule(BaseRule):
    """CIS Benchmark 4.1.2: Ensure Web Filter Profile Blocks Malicious Categories."""

    rule_id = "CIS-4.1.2"
    name = "Ensure Web Filter Blocks Malicious Categories"
    description = (
        "Verifica que el perfil de Filtrado Web bloquee categorías de alto riesgo "
        "como Malware, Botnets, Phishing y Spam URLs."
    )
    category = "Security Profiles"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    required_endpoint = "api/v2/cmdb/webfilter/profile"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        wf_profiles = (
            parsed_config.get("config webfilter profile")
            or parsed_config.get("webfilter profile")
            or parsed_config
        )

        has_profiles = False
        if isinstance(wf_profiles, dict):
            results = wf_profiles.get("results", wf_profiles)
            if results:
                has_profiles = True

        if not has_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No existen perfiles de Web Filter configurados",
                expected_value="Al menos un perfil de Web Filter configurado y bloqueando categorías de riesgo",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config webfilter profile\n"
                    "       edit \"default\"\n"
                    "           config ftgd-wf\n"
                    "               config filters\n"
                    "                   edit 1\n"
                    "                       set category 26\n"
                    "                       set action block\n"
                    "                   next\n"
                    "               end\n"
                    "           end\n"
                    "       next\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Profiles > Web Filter.\n"
                    "   b. Edite el perfil deseado y active 'FortiGuard category based filter'.\n"
                    "   c. Establezca en 'Block' las categorías de 'Potentially Liable' y 'Security Risk' (Malware, Phishing, etc.).\n"
                    "   d. Guarde los cambios."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Perfiles de Filtrado Web presentes en el sistema",
            expected_value="Categorías maliciosas bloqueadas en Web Filter",
        )


# =============================================================================
# CIS 4.1.3 - Ensure IPS Sensor is Configured with High Severity Rules
# =============================================================================
@register_rule
class EnsureIPSSensorConfiguredRule(BaseRule):
    """CIS Benchmark 4.1.3: Ensure IPS Sensor is Configured with High Severity Rules."""

    rule_id = "CIS-4.1.3"
    name = "Ensure IPS Sensor Blocks High/Critical Attacks"
    description = (
        "Garantiza que el sensor del Sistema de Prevención de Intrusiones (IPS) esté "
        "configurado para bloquear (block/reset) amenazas de severidad Alta y Crítica."
    )
    category = "Security Profiles"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    required_endpoint = "api/v2/cmdb/ips/sensor"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        ips_sensors = (
            parsed_config.get("config ips sensor")
            or parsed_config.get("ips sensor")
            or parsed_config
        )

        has_sensors = False
        if isinstance(ips_sensors, dict):
            results = ips_sensors.get("results", ips_sensors)
            if results:
                has_sensors = True

        if not has_sensors:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No hay sensores IPS configurados",
                expected_value="Al menos un sensor IPS activo bloqueando severidades High y Critical",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config ips sensor\n"
                    "       edit \"default\"\n"
                    "           config entries\n"
                    "               edit 1\n"
                    "                   set severity high critical\n"
                    "                   set action block\n"
                    "               next\n"
                    "           end\n"
                    "       next\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Profiles > Intrusion Prevention.\n"
                    "   b. Cree un sensor o edite el existente.\n"
                    "   c. Añada una regla/filtro para severidades 'High' y 'Critical' definiendo la acción en 'Block'.\n"
                    "   d. Guarde la configuración."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Sensores IPS configurados correctamente",
            expected_value="Sensores IPS bloqueando firmas de alta severidad",
        )


# =============================================================================
# CIS 4.1.4 - Ensure Application Control is Configured to Block Risky Apps
# =============================================================================
@register_rule
class EnsureAppControlConfiguredRule(BaseRule):
    """CIS Benchmark 4.1.4: Ensure Application Control is Configured to Block Risky Apps."""

    rule_id = "CIS-4.1.4"
    name = "Ensure Application Control Blocks High Risk Apps"
    description = (
        "Verifica que el perfil de Control de Aplicaciones esté activo bloqueando aplicaciones "
        "de alto riesgo o evasivas (Proxy, P2P, Tunneling)."
    )
    category = "Security Profiles"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    required_endpoint = "api/v2/cmdb/application/list"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        app_list = (
            parsed_config.get("config application list")
            or parsed_config.get("application list")
            or parsed_config
        )

        has_app_control = False
        if isinstance(app_list, dict):
            results = app_list.get("results", app_list)
            if results:
                has_app_control = True

        if not has_app_control:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No existen perfiles de Application Control configurados",
                expected_value="Al menos un perfil de Application Control bloqueando aplicaciones de riesgo",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config application list\n"
                    "       edit \"default\"\n"
                    "           config entries\n"
                    "               edit 1\n"
                    "                   set category 2\n"
                    "                   set action block\n"
                    "               next\n"
                    "           end\n"
                    "       next\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Profiles > Application Control.\n"
                    "   b. Seleccione el perfil y configure en 'Block' las categorías de riesgo (Peer.to.Peer, Proxy, etc.).\n"
                    "   c. Guarde los cambios."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Perfiles de Control de Aplicaciones configurados",
            expected_value="Bloqueo de aplicaciones no autorizadas/riesgosas activo",
        )


# =============================================================================
# CIS 4.1.5 - Ensure DNS Filter is Enabled and Blocks Malicious Domains
# =============================================================================
@register_rule
class EnsureDNSFilterConfiguredRule(BaseRule):
    """CIS Benchmark 4.1.5: Ensure DNS Filter is Enabled and Blocks Malicious Domains."""

    rule_id = "CIS-4.1.5"
    name = "Ensure DNS Filter Blocks Malicious Domains"
    description = (
        "Garantiza que el perfil de DNS Filter bloquee activamente resoluciones de dominio "
        "asociadas a Botnets, Malware, Phishing y sitios C&C (Command & Control)."
    )
    category = "Security Profiles"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    required_endpoint = "api/v2/cmdb/dnsfilter/profile"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        dns_profiles = (
            parsed_config.get("config dnsfilter profile")
            or parsed_config.get("dnsfilter profile")
            or parsed_config
        )

        unprotected_profiles = []
        has_profiles = False

        if isinstance(dns_profiles, dict):
            results = dns_profiles.get("results", dns_profiles)

            if isinstance(results, list):
                if results:
                    has_profiles = True
                for profile in results:
                    if isinstance(profile, dict):
                        prof_name = profile.get("name", profile.get("q_origin_key", "desconocido"))
                        block_botnet = profile.get("block-botnet", "disable")
                        if block_botnet != "enable":
                            unprotected_profiles.append(prof_name)

            elif isinstance(results, dict):
                if results:
                    has_profiles = True
                for profile_name, profile_data in results.items():
                    if isinstance(profile_data, dict):
                        block_botnet = profile_data.get("block-botnet", "disable")
                        if block_botnet != "enable":
                            unprotected_profiles.append(profile_name)

        if not has_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No existen perfiles de DNS Filter configurados",
                expected_value="Al menos un perfil de DNS Filter bloqueando dominios maliciosos",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config dnsfilter profile\n"
                    "       edit \"default\"\n"
                    "           set block-botnet enable\n"
                    "       next\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Profiles > DNS Filter.\n"
                    "   b. Edite el perfil 'default' o cree uno nuevo.\n"
                    "   c. Active la casilla 'Block DNS requests to known botnet C&C servers'.\n"
                    "   d. Guarde los cambios haciendo clic en 'Apply'."
                ),
            )

        if unprotected_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Perfiles DNS Filter sin 'block-botnet' activo: {', '.join(unprotected_profiles)}",
                expected_value="block-botnet: enable en todos los perfiles de DNS Filter",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   config dnsfilter profile\n"
                    "       edit \"<nombre_perfil>\"\n"
                    "           set block-botnet enable\n"
                    "       next\n"
                    "   end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Profiles > DNS Filter.\n"
                    "   b. Edite los perfiles indicados.\n"
                    "   c. Habilite la opción 'Block DNS requests to known botnet C&C servers'.\n"
                    "   d. Guarde los cambios."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Bloqueo de dominios Botnet/C&C activo en todos los perfiles DNS Filter",
            expected_value="block-botnet: enable",
        )

from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 4.1.6 - Ensure Botnet C&C IP Blocking is Enabled on Interfaces or IPS
# =============================================================================
@register_rule
class EnsureBotnetIPBlockingRule(BaseRule):
    """CIS Benchmark 4.1.6: Ensure Botnet C&C IP Blocking is Enabled."""

    rule_id = "CIS-4.1.6"
    name = "Ensure Botnet C&C IP Blocking Enabled"
    description = (
        "Verifica que la funcionalidad de bloqueo de conexiones hacia o desde direcciones IP "
        "de servidores Botnet/C&C conocidas de FortiGuard esté activa globalmente o en las interfaces."
    )
    category = "Security Profiles"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/interface"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interface_config = (
            parsed_config.get("config system interface")
            or parsed_config.get("system interface")
            or parsed_config
        )

        disabled_interfaces = []

        if isinstance(interface_config, dict):
            results = interface_config.get("results", interface_config)

            if isinstance(results, list):
                for iface in results:
                    if isinstance(iface, dict):
                        iface_name = str(iface.get("name", iface.get("q_origin_key", "")))
                        role = str(iface.get("role", "")).lower()

                        if role == "wan" or iface_name.lower().startswith("wan"):
                            botnet_scan = str(iface.get("scan-botnet-connections", "block")).lower()
                            if botnet_scan == "disable":
                                disabled_interfaces.append(iface_name)

            elif isinstance(results, dict):
                for iface_name, iface_data in results.items():
                    if isinstance(iface_data, dict):
                        role = str(iface_data.get("role", "")).lower()
                        if role == "wan" or str(iface_name).lower().startswith("wan"):
                            botnet_scan = str(iface_data.get("scan-botnet-connections", "block")).lower()
                            if botnet_scan == "disable":
                                disabled_interfaces.append(str(iface_name))

        if disabled_interfaces:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Detección de IPs Botnet deshabilitada en WANs: {', '.join(disabled_interfaces)}",
                expected_value="scan-botnet-connections: block en interfaces externas/WAN",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Habilite el escaneo y bloqueo de conexiones Botnet en la interfaz:\n"
                    "     config system interface\n"
                    "         edit \"<interfaz_wan>\"\n"
                    "             set scan-botnet-connections block\n"
                    "         next\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Network > Interfaces.\n"
                    "   b. Edite la interfaz WAN deseada.\n"
                    "   c. En la sección 'Network', habilite la opción 'Scan Outgoing Connections to Botnet Sites' y seleccione la acción 'Block'.\n"
                    "   d. Guarde los cambios haciendo clic en 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Escaneo y bloqueo de IPs Botnet activo en interfaces externas",
            expected_value="scan-botnet-connections en 'block' o 'monitor'",
        )


# =============================================================================
# CIS 4.1.7 - Ensure Outbound Inline Cloud/FortiSandbox Inspection is Configured
# =============================================================================
@register_rule
class EnsureFortiSandboxIntegrationRule(BaseRule):
    """CIS Benchmark 4.1.7: Ensure FortiSandbox Inspection is Configured."""

    rule_id = "CIS-4.1.7"
    name = "Ensure FortiSandbox Integration"
    description = (
        "Evalúa si el FortiGate está integrado con FortiSandbox (Cloud o Appliance local) "
        "para el análisis dinámico de amenazas de día cero (Zero-Day) en archivos sospechosos."
    )
    category = "Security Profiles"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/fortisandbox"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        sandbox_config = (
            parsed_config.get("config system fortisandbox")
            or parsed_config.get("system fortisandbox")
            or parsed_config
        )

        status = "disable"

        if isinstance(sandbox_config, dict):
            results = sandbox_config.get("results", sandbox_config)

            if isinstance(results, list) and len(results) > 0:
                first_item = results[0]
                if isinstance(first_item, dict):
                    status = str(first_item.get("status", "disable")).lower()
            elif isinstance(results, dict):
                status = str(results.get("status", "disable")).lower()

        if status != "enable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"system fortisandbox status: {status}",
                expected_value="Integración con FortiSandbox (Cloud/Inline) habilitada",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Habilite el servicio de FortiSandbox Cloud o de Appliance local:\n"
                    "     config system fortisandbox\n"
                    "         set status enable\n"
                    "         set server \"fortisandbox-cloud\"\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Security Fabric > Fabric Connectors.\n"
                    "   b. Haga doble clic en el conector 'FortiSandbox'.\n"
                    "   c. Marque la casilla 'Enable' y seleccione el tipo (FortiSandbox Cloud o Appliance On-Premise).\n"
                    "   d. Guarde la configuración haciendo clic en 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Integración con FortiSandbox habilitada correctamente",
            expected_value="system fortisandbox status: enable",
        )