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

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interface_config = parsed_config.get("config system interface") or parsed_config.get("system interface", {})

        enabled_interfaces = []

        if isinstance(interface_config, dict):
            for iface_name, iface_data in interface_config.items():
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
                    "config system interface\n"
                    "    edit \"<nombre_interfaz>\"\n"
                    "        set cdp disable\n"
                    "    next\n"
                    "end"
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

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interface_config = parsed_config.get("config system interface") or parsed_config.get("system interface", {})

        exposed_interfaces = []

        if isinstance(interface_config, dict):
            for iface_name, iface_data in interface_config.items():
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
                    "config system interface\n"
                    "    edit \"<nombre_interfaz>\"\n"
                    "        set lldp-transmission disable\n"
                    "        set lldp-reception disable\n"
                    "    next\n"
                    "end"
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

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        interface_config = parsed_config.get("config system interface") or parsed_config.get("system interface", {})

        wan_ping_interfaces = []

        if isinstance(interface_config, dict):
            for iface_name, iface_data in interface_config.items():
                if isinstance(iface_data, dict):
                    role = iface_data.get("role", "").lower()
                    allowaccess = iface_data.get("allowaccess", "").lower().split()

                    # Si el rol es 'wan' o la interfaz es típicamente externa (wan1, wan2, etc.)
                    is_external = role == "wan" or iface_name.lower().startswith("wan")

                    if is_external and "ping" in allowaccess:
                        wan_ping_interfaces.append(iface_name)

        if wan_ping_interfaces:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"PING permitido en interfaces externas: {', '.join(wan_ping_interfaces)}",
                expected_value="Remover 'ping' de 'allowaccess' en interfaces de tipo WAN/Externas",
                remediation_cmd=(
                    "config system interface\n"
                    "    edit \"<interfaz_wan>\"\n"
                    "        set allowaccess https ssh  # Excluir 'ping'\n"
                    "    next\n"
                    "end"
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

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        ident_serv = global_config.get("ident-accept", "disable")

        if ident_serv != "disable":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"ident-accept: {ident_serv}",
                expected_value="ident-accept: disable",
                remediation_cmd=(
                    "config system global\n"
                    "    set ident-accept disable\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Servicio Ident deshabilitado correctamente",
            expected_value="ident-accept: disable",
        )


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

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        dns_config = parsed_config.get("config system dns") or parsed_config.get("system dns", {})

        primary = dns_config.get("primary")
        secondary = dns_config.get("secondary")

        if not primary or primary == "0.0.0.0":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"DNS primario: {primary or 'No definido'}",
                expected_value="DNS primario debe estar configurado con una IP válida",
                remediation_cmd=(
                    "config system dns\n"
                    "    set primary 1.1.1.1\n"
                    "    set secondary 1.0.0.1\n"
                    "end"
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

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        session_helpers = parsed_config.get("config system session-helper") or parsed_config.get("system session-helper", {})

        active_helpers = []
        if isinstance(session_helpers, dict):
            for entry_id, helper_data in session_helpers.items():
                if isinstance(helper_data, dict):
                    name = helper_data.get("name", "").lower()
                    if name in ["sip", "h323"]:
                        active_helpers.append(f"{name} (ID: {entry_id})")

        if active_helpers:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Session helpers activos: {', '.join(active_helpers)}",
                expected_value="Eliminar asistentes de sesión SIP y H.323 si no se utilizan",
                remediation_cmd=(
                    "config system session-helper\n"
                    "    # Eliminar las entradas correspondientes a sip y h323 (ejemplo ID 13 y 12)\n"
                    "    delete <ID_HELPER>\n"
                    "end"
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

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        snmp_sys = parsed_config.get("config system snmp sysinfo") or parsed_config.get("system snmp sysinfo", {})
        snmp_status = snmp_sys.get("status", "disable")

        if snmp_status == "disable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="SNMP está totalmente deshabilitado",
                expected_value="SNMP deshabilitado o usando solo SNMPv3",
            )

        # Si SNMP está habilitado, verificar si hay comunidades v1/v2c configuradas
        snmp_community = parsed_config.get("config system snmp community") or parsed_config.get("system snmp community", {})

        if snmp_community and len(snmp_community) > 0:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="SNMP está habilitado con comunidades v1/v2c activas",
                expected_value="Eliminar comunidades v1/v2c y utilizar únicamente 'config system snmp user' (v3)",
                remediation_cmd=(
                    "config system snmp community\n"
                    "    purge  # Elimina comunidades v1/v2c insecure\n"
                    "end"
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

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        central_config = parsed_config.get("config system central-management") or parsed_config.get("system central-management", {})

        enc_algorithm = central_config.get("enc-algorithm", "high")

        if enc_algorithm == "default" or enc_algorithm == "low":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"enc-algorithm: {enc_algorithm}",
                expected_value="enc-algorithm: high",
                remediation_cmd=(
                    "config system central-management\n"
                    "    set enc-algorithm high\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Cifrado alto activo para la comunicación con FortiManager",
            expected_value="enc-algorithm: high",
        )