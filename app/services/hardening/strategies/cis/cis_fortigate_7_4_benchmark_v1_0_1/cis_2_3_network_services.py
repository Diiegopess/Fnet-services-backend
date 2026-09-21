from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 2.3.1 - Ensure 'CDP' is Disabled on All Interfaces
# =============================================================================
@register_rule
class DisableCDPRule(BaseRule):
    """CIS Benchmark 2.3.1: Ensure 'CDP' is Disabled on All Interfaces."""

    rule_id = "CIS-2.3.1"
    name = "Disable CDP on Interfaces"
    description = (
        "Deshabilita el protocolo Cisco Discovery Protocol (CDP) en todas las interfaces "
        "para evitar la divulgación innecesaria de información de red."
    )
    category = "Network / Services"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/interface"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interface_config = parsed_config.get("config system interface") or parsed_config.get("system interface") or parsed_config

        enabled_interfaces = []

        if isinstance(interface_config, dict):
            results = interface_config.get("results", interface_config)

            if isinstance(results, list):
                for iface in results:
                    if isinstance(iface, dict):
                        iface_name = iface.get("name", "Unknown")
                        cdp = iface.get("cdp", "disable")
                        if cdp == "enable":
                            enabled_interfaces.append(iface_name)
            elif isinstance(results, dict):
                for iface_name, iface_data in results.items():
                    if isinstance(iface_data, dict):
                        cdp = iface_data.get("cdp", "disable")
                        if cdp == "enable":
                            enabled_interfaces.append(iface_name)

        if enabled_interfaces:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"CDP habilitado en: {', '.join(enabled_interfaces)}",
                expected_value="cdp: disable en todas las interfaces",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Deshabilite el protocolo CDP en la interfaz deseada:\n"
                    "     config system interface\n"
                    "         edit \"<nombre_interfaz>\"\n"
                    "             set cdp disable\n"
                    "         next\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: La opción para habilitar o deshabilitar CDP por interfaz "
                    "no está disponible en el portal Web estándar y debe configurarse exclusivamente vía CLI."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="CDP deshabilitado en todas las interfaces configuradas",
            expected_value="cdp: disable",
        )


# =============================================================================
# CIS 2.3.2 - Ensure 'LLDP' Transmit and Receive are Disabled
# =============================================================================
@register_rule
class DisableLLDPRule(BaseRule):
    """CIS Benchmark 2.3.2: Ensure 'LLDP' Transmit and Receive are Disabled."""

    rule_id = "CIS-2.3.2"
    name = "Disable LLDP on Interfaces"
    description = (
        "Deshabilita la transmisión y recepción del protocolo LLDP (Link Layer Discovery Protocol) "
        "en las interfaces para reducir el reconocimiento de topología por terceros."
    )
    category = "Network / Services"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/interface"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interface_config = parsed_config.get("config system interface") or parsed_config.get("system interface") or parsed_config

        exposed_interfaces = []

        if isinstance(interface_config, dict):
            results = interface_config.get("results", interface_config)

            if isinstance(results, list):
                for iface in results:
                    if isinstance(iface, dict):
                        iface_name = iface.get("name", "Unknown")
                        lldp_transmission = iface.get("lldp-transmission", "disable")
                        lldp_reception = iface.get("lldp-reception", "disable")

                        if lldp_transmission != "disable" or lldp_reception != "disable":
                            exposed_interfaces.append(
                                f"{iface_name} (tx: {lldp_transmission}, rx: {lldp_reception})"
                            )
            elif isinstance(results, dict):
                for iface_name, iface_data in results.items():
                    if isinstance(iface_data, dict):
                        lldp_transmission = iface_data.get("lldp-transmission", "disable")
                        lldp_reception = iface_data.get("lldp-reception", "disable")

                        if lldp_transmission != "disable" or lldp_reception != "disable":
                            exposed_interfaces.append(
                                f"{iface_name} (tx: {lldp_transmission}, rx: {lldp_reception})"
                            )

        if exposed_interfaces:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"LLDP activo en: {'; '.join(exposed_interfaces)}",
                expected_value="lldp-transmission: disable y lldp-reception: disable en todas las interfaces",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Deshabilite la transmisión y recepción de LLDP en la interfaz:\n"
                    "     config system interface\n"
                    "         edit \"<nombre_interfaz>\"\n"
                    "             set lldp-transmission disable\n"
                    "             set lldp-reception disable\n"
                    "         next\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Vaya a Network > Interfaces.\n"
                    "   b. Edite la interfaz correspondiente.\n"
                    "   c. Despliegue el panel 'Advanced Options' o 'LLDP'.\n"
                    "   d. Desmarque o deshabilite las opciones 'LLDP Transmit' y 'LLDP Receive'.\n"
                    "   e. Aplique los cambios haciendo clic en 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="LLDP totalmente deshabilitado en todas las interfaces",
            expected_value="lldp-transmission y lldp-reception en disable",
        )


# =============================================================================
# CIS 2.3.3 - Ensure 'PING' Access is Disabled on External Interfaces
# =============================================================================
@register_rule
class DisableExternalPingRule(BaseRule):
    """CIS Benchmark 2.3.3: Ensure 'PING' Access is Disabled on External Interfaces."""

    rule_id = "CIS-2.3.3"
    name = "Disable Ping on External Interfaces"
    description = (
        "Deshabilita la respuesta a PING (ICMP Echo Request) en interfaces externas "
        "o WAN para prevenir el mapeo activo de la red."
    )
    category = "Network / Services"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/interface"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interface_config = parsed_config.get("config system interface") or parsed_config.get("system interface") or parsed_config

        wan_ping_interfaces = []

        if isinstance(interface_config, dict):
            results = interface_config.get("results", interface_config)

            if isinstance(results, list):
                for iface in results:
                    if isinstance(iface, dict):
                        iface_name = iface.get("name", "Unknown")
                        role = str(iface.get("role", "")).lower()
                        allowaccess = str(iface.get("allowaccess", "")).lower().split()

                        is_external = role == "wan" or iface_name.lower().startswith("wan")

                        if is_external and "ping" in allowaccess:
                            wan_ping_interfaces.append(iface_name)
            elif isinstance(results, dict):
                for iface_name, iface_data in results.items():
                    if isinstance(iface_data, dict):
                        role = str(iface_data.get("role", "")).lower()
                        allowaccess = str(iface_data.get("allowaccess", "")).lower().split()

                        is_external = role == "wan" or iface_name.lower().startswith("wan")

                        if is_external and "ping" in allowaccess:
                            wan_ping_interfaces.append(iface_name)

        if wan_ping_interfaces:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"PING permitido en interfaces externas: {', '.join(wan_ping_interfaces)}",
                expected_value="Remover 'ping' de 'allowaccess' en interfaces de tipo WAN/Externas",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Remueva PING de la lista de accesos permitidos en la interfaz externa:\n"
                    "     config system interface\n"
                    "         edit \"<interfaz_wan>\"\n"
                    "             set allowaccess https ssh  # Excluir 'ping'\n"
                    "         next\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Network > Interfaces.\n"
                    "   b. Seleccione la interfaz WAN afectada y haga clic en 'Edit'.\n"
                    "   c. En la sección 'Administrative Access', desmarque la casilla 'PING'.\n"
                    "   d. Guarde los cambios haciendo clic en 'OK'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="PING deshabilitado en interfaces externas/WAN identificadas",
            expected_value="PING no permitido en la interfaz WAN",
        )


# =============================================================================
# CIS 2.3.4 - Ensure 'Ident' Service is Disabled
# =============================================================================
@register_rule
class DisableIdentServiceRule(BaseRule):
    """CIS Benchmark 2.3.4: Ensure 'Ident' Service is Disabled."""

    rule_id = "CIS-2.3.4"
    name = "Disable Ident Service"
    description = (
        "Garantiza que el servicio de identificación (puerto TCP 113) esté deshabilitado "
        "para evitar la fuga de nombres de usuarios de procesos."
    )
    category = "Network / Services"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/global"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global") or parsed_config

        ident_serv = global_config.get("ident-accept", "disable")

        if ident_serv != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"ident-accept: {ident_serv}",
                expected_value="ident-accept: disable",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Deshabilite la aceptación de conexiones del servicio Ident:\n"
                    "     config system global\n"
                    "         set ident-accept disable\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: El parámetro de aceptación del servicio Ident (`ident-accept`) "
                    "no está disponible en la interfaz gráfica y debe configurarse exclusivamente vía CLI."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Servicio Ident deshabilitado correctamente",
            expected_value="ident-accept: disable",
        )
from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 2.3.5 - Ensure 'DNS' Server Settings are Secured
# =============================================================================
@register_rule
class EnsureSecureDNSRule(BaseRule):
    """CIS Benchmark 2.3.5: Ensure 'DNS' Server Settings are Secured."""

    rule_id = "CIS-2.3.5"
    name = "Secure System DNS Settings"
    description = (
        "Verifica que la resolución de nombres DNS esté configurada utilizando servidores "
        "confiables y que se habilite el protocolo DoH/DoT si aplica."
    )
    category = "Network / Services"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/dns"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        dns_config = (
            parsed_config.get("config system dns")
            or parsed_config.get("system dns")
            or parsed_config
        )

        if isinstance(dns_config, dict) and "results" in dns_config:
            dns_config = dns_config["results"]

        primary = dns_config.get("primary")
        secondary = dns_config.get("secondary")

        if not primary or primary == "0.0.0.0":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"DNS primario: {primary or 'No definido'}",
                expected_value="DNS primario debe estar configurado con una IP válida",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Configure direcciones de servidores DNS confiables:\n"
                    "     config system dns\n"
                    "         set primary 1.1.1.1\n"
                    "         set secondary 1.0.0.1\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a Network > DNS.\n"
                    "   b. En 'DNS Servers', seleccione 'Specify'.\n"
                    "   c. Ingrese las direcciones IP para el servidor Primary y Secondary DNS.\n"
                    "   d. Guarde los cambios haciendo clic en 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"DNS configurado correctamente (Primario: {primary}, Secundario: {secondary or 'No definido'})",
            expected_value="Servidores DNS primario y secundario válidos configurados",
        )


# =============================================================================
# CIS 2.3.6 - Ensure 'SIP' and 'H.323' Session Helpers / ALG are Disabled
# =============================================================================
@register_rule
class DisableSIPH323ALGRule(BaseRule):
    """CIS Benchmark 2.3.6: Ensure SIP and H.323 Session Helpers / ALG are Disabled."""

    rule_id = "CIS-2.3.6"
    name = "Disable SIP/H.323 Session Helpers"
    description = (
        "Deshabilita los asistentes de sesión (ALG) para SIP y H.323 si no son requeridos, "
        "para reducir la superficie de ataque e inestabilidad en el procesamiento de paquetes."
    )
    category = "Network / Services"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/session-helper"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        session_helpers = (
            parsed_config.get("config system session-helper")
            or parsed_config.get("system session-helper")
            or parsed_config
        )

        active_helpers = []

        if isinstance(session_helpers, dict):
            results = session_helpers.get("results", session_helpers)

            if isinstance(results, list):
                for helper in results:
                    if isinstance(helper, dict):
                        name = str(helper.get("name", "")).lower()
                        entry_id = helper.get("id", "N/A")
                        if name in ["sip", "h323"]:
                            active_helpers.append(f"{name} (ID: {entry_id})")
            elif isinstance(results, dict):
                for entry_id, helper_data in results.items():
                    if isinstance(helper_data, dict):
                        name = str(helper_data.get("name", "")).lower()
                        if name in ["sip", "h323"]:
                            active_helpers.append(f"{name} (ID: {entry_id})")

        if active_helpers:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Session helpers activos: {', '.join(active_helpers)}",
                expected_value="Eliminar asistentes de sesión SIP y H.323 si no se utilizan",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Elimine las entradas asociadas a sip y h323 identificando su ID:\n"
                    "     config system session-helper\n"
                    "         delete <ID_HELPER>\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: La gestión técnica de Session Helpers no cuenta con un módulo de administración directas en la GUI "
                    "y debe realizarse mediante la consola de CLI."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Session helpers de SIP y H.323 no encontrados o eliminados",
            expected_value="SIP y H.323 session helpers deshabilitados",
        )


# =============================================================================
# CIS 2.3.7 - Ensure 'Snmp' is Disabled or Using SNMPv3
# =============================================================================
@register_rule
class EnsureSNMPv3OnlyRule(BaseRule):
    """CIS Benchmark 2.3.7: Ensure 'SNMP' is Disabled or Using SNMPv3."""

    rule_id = "CIS-2.3.7"
    name = "Ensure Secure SNMP Configuration"
    description = (
        "Exige que SNMP esté deshabilitado o que utilice exclusivamente SNMPv3 "
        "con autenticación y cifrado (authPriv), evitando SNMPv1/v2c en texto plano."
    )
    category = "Network / Services"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system.snmp/sysinfo"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        snmp_sys = (
            parsed_config.get("config system snmp sysinfo")
            or parsed_config.get("system snmp sysinfo")
            or parsed_config
        )

        if isinstance(snmp_sys, dict) and "results" in snmp_sys:
            snmp_sys = snmp_sys["results"]

        snmp_status = snmp_sys.get("status", "disable")

        if snmp_status == "disable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="SNMP está totalmente deshabilitado",
                expected_value="SNMP deshabilitado o usando solo SNMPv3",
            )

        # Si SNMP está habilitado, verificar si existen comunidades v1/v2c
        snmp_community = (
            parsed_config.get("config system snmp community")
            or parsed_config.get("system snmp community", {})
        )

        has_communities = False
        if isinstance(snmp_community, dict):
            results = snmp_community.get("results", snmp_community)
            if results:
                has_communities = True

        if has_communities:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="SNMP está habilitado con comunidades v1/v2c activas",
                expected_value="Eliminar comunidades v1/v2c y utilizar únicamente 'config system snmp user' (v3)",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Elimine las comunidades de SNMP v1/v2c o deshabilite el servicio:\n"
                    "     config system snmp community\n"
                    "         purge\n"
                    "     end\n"
                    "   (Opcional) Para usar SNMPv3 únicamente:\n"
                    "     config system snmp user\n"
                    "         edit \"<usuario_v3>\"\n"
                    "             set security-level auth-priv\n"
                    "         next\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   a. Ingrese a System > SNMP.\n"
                    "   b. Deshabilite el conmutador 'SNMP Agent' si no requiere monitoreo, o bien en la sección 'SNMP v1/v2c' "
                    "elimine cualquier comunidad existente.\n"
                    "   c. Cree las cuentas requeridas exclusivamente en la sección 'SNMP v3'.\n"
                    "   d. Aplique los cambios con 'Apply'."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="SNMP habilitado exclusivamente con SNMPv3",
            expected_value="SNMPv3 configurado sin comunidades v1/v2c",
        )


# =============================================================================
# CIS 2.3.8 - Ensure 'FortiManager' Connection is Encrypted
# =============================================================================
@register_rule
class EnsureEncryptedFortiManagerRule(BaseRule):
    """CIS Benchmark 2.3.8: Ensure 'FortiManager' Connection is Encrypted."""

    rule_id = "CIS-2.3.8"
    name = "Encrypt FortiManager Connection"
    description = (
        "Garantiza que la comunicación con FortiManager utilice cifrado alto "
        "y validación estricta de certificados de servidor."
    )
    category = "Network / Services"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    # Endpoint para API REST de FortiOS
    required_endpoint = "api/v2/cmdb/system/central-management"

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        central_config = (
            parsed_config.get("config system central-management")
            or parsed_config.get("system central-management")
            or parsed_config
        )

        if isinstance(central_config, dict) and "results" in central_config:
            central_config = central_config["results"]

        enc_algorithm = central_config.get("enc-algorithm", "high")

        if enc_algorithm in ["default", "low"]:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"enc-algorithm: {enc_algorithm}",
                expected_value="enc-algorithm: high",
                remediation_cmd=(
                    "PASOS DE REMEDIACIÓN:\n\n"
                    "1. A través de la CLI de FortiGate:\n"
                    "   Asegure un nivel de cifrado alto para la conexión centralizada:\n"
                    "     config system central-management\n"
                    "         set enc-algorithm high\n"
                    "     end\n\n"
                    "2. A través de la Interfaz Gráfica (GUI):\n"
                    "   * Nota: El nivel de algoritmo de cifrado para la gestión centralizada "
                    "únicamente se encuentra accesible mediante la configuración vía CLI."
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Cifrado alto activo para la comunicación con FortiManager",
            expected_value="enc-algorithm: high",
        )