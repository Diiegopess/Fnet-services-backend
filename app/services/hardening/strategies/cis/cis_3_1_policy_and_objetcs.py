from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# CIS 3.1.1 - Ensure 'ALL' is Not Used as Source/Destination in Sensitive Policies
# =============================================================================
@register_rule
class AvoidAllInPoliciesRule(BaseRule):
    """CIS Benchmark 3.1.1: Ensure 'ALL' is Not Used as Source/Destination in Policies."""

    rule_id = "CIS-3.1.1"
    name = "Avoid 'ALL' Address Object in Accept Policies"
    description = (
        "Garantiza que las políticas de firewall de tipo ACCEPT no utilicen 'all' "
        "en origen y destino simultáneamente, aplicando el principio de mínimo privilegio."
    )
    category = "Policy and Objects"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy") or parsed_config.get("firewall policy", {})

        overly_permissive = []

        if isinstance(policies, dict):
            for policy_id, policy_data in policies.items():
                if isinstance(policy_data, dict):
                    action = policy_data.get("action", "accept")
                    status = policy_data.get("status", "enable")

                    if action == "accept" and status != "disable":
                        srcaddr = str(policy_data.get("srcaddr", "")).lower()
                        dstaddr = str(policy_data.get("dstaddr", "")).lower()

                        if "all" in srcaddr.split() and "all" in dstaddr.split():
                            overly_permissive.append(str(policy_id))

        if overly_permissive:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas permitiendo de 'all' a 'all': IDs {', '.join(overly_permissive)}",
                expected_value="Restringir los objetos de red de origen o destino a IPs/redes específicas",
                remediation_cmd=(
                    "config firewall policy\n"
                    "    edit <ID_POLITICA>\n"
                    "        set srcaddr <Objeto_Origen_Especifico>\n"
                    "        set dstaddr <Objeto_Destino_Especifico>\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="No hay políticas activas que permitan tráfico irrestricto de 'all' a 'all'",
            expected_value="Origen y destino acotados en políticas de aceptación",
        )


# =============================================================================
# CIS 3.1.2 - Ensure Unused/Unreferenced Policies are Disabled or Removed
# =============================================================================
@register_rule
class DisableUnusedPoliciesRule(BaseRule):
    """CIS Benchmark 3.1.2: Ensure Unused Policies are Disabled or Removed."""

    rule_id = "CIS-3.1.2"
    name = "Ensure Policies Have Log Traffic Enabled"
    description = (
        "Verifica que las políticas de firewall activas tengan habilitado el registro de tráfico "
        "(logtraffic) para auditoría y visibilidad."
    )
    category = "Policy and Objects"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy") or parsed_config.get("firewall policy", {})

        unlogged_policies = []

        if isinstance(policies, dict):
            for policy_id, policy_data in policies.items():
                if isinstance(policy_data, dict):
                    action = policy_data.get("action", "accept")
                    status = policy_data.get("status", "enable")
                    logtraffic = policy_data.get("logtraffic", "disable")

                    if action == "accept" and status != "disable" and logtraffic == "disable":
                        unlogged_policies.append(str(policy_id))

        if unlogged_policies:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas de aceptación sin log de tráfico: IDs {', '.join(unlogged_policies)}",
                expected_value="logtraffic: all o utm en todas las políticas activas",
                remediation_cmd=(
                    "config firewall policy\n"
                    "    edit <ID_POLITICA>\n"
                    "        set logtraffic all\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las políticas activas generan registros de tráfico",
            expected_value="logtraffic configurado en todas las políticas",
        )


# =============================================================================
# CIS 3.1.3 - Ensure 'ANY' Service is Avoided in Accept Policies
# =============================================================================
@register_rule
class AvoidAnyServiceInPoliciesRule(BaseRule):
    """CIS Benchmark 3.1.3: Ensure 'ANY' Service is Avoided in Accept Policies."""

    rule_id = "CIS-3.1.3"
    name = "Avoid 'ALL' Service in Accept Policies"
    description = (
        "Garantiza que las políticas de firewall no utilicen el servicio 'ALL' o 'ANY' "
        "para evitar la apertura indiscriminada de todos los puertos TCP/UDP."
    )
    category = "Policy and Objects"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy") or parsed_config.get("firewall policy", {})

        any_service_policies = []

        if isinstance(policies, dict):
            for policy_id, policy_data in policies.items():
                if isinstance(policy_data, dict):
                    action = policy_data.get("action", "accept")
                    status = policy_data.get("status", "enable")
                    service = str(policy_data.get("service", "")).lower()

                    if action == "accept" and status != "disable" and "all" in service.split():
                        any_service_policies.append(str(policy_id))

        if any_service_policies:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas que permiten el servicio 'ALL': IDs {', '.join(any_service_policies)}",
                expected_value="Especificar los servicios/puertos explícitos requeridos por el negocio",
                remediation_cmd=(
                    "config firewall policy\n"
                    "    edit <ID_POLITICA>\n"
                    "        set service \"HTTPS\" \"HTTP\"\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="No hay políticas de aceptación con servicio indiscriminado 'ALL'",
            expected_value="Servicios explícitos definidos en cada política",
        )


# =============================================================================
# CIS 3.1.4 - Ensure Explicit Default Deny Rule Exists at the End
# =============================================================================
@register_rule
class EnsureImplicitDenyLogRule(BaseRule):
    """CIS Benchmark 3.1.4: Ensure Implicit Deny Policy Logs Traffic."""

    rule_id = "CIS-3.1.4"
    name = "Log Implicit Deny Policy Traffic"
    description = (
        "Verifica que la regla implícita de denegación al final de la tabla (ID 0) "
        "tenga activo el registro de logs para auditoría de tráfico descartado."
    )
    category = "Policy and Objects"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policy_0 = parsed_config.get("config firewall policy 0") or {}
        global_config = parsed_config.get("config system global") or parsed_config.get("system global", {})

        # También se valida a nivel global según la versión de FortiOS
        block_log = global_config.get("block-session-timer", None)
        policy_0_log = policy_0.get("logtraffic", "disable")

        if policy_0_log == "disable" and block_log is None:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Regla implícita de denegación (ID 0) sin registro de logs activo",
                expected_value="logtraffic: all en la política implícita 0 o política explícita deny al final",
                remediation_cmd=(
                    "config firewall policy\n"
                    "    edit 0\n"
                    "        set logtraffic all\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Registro de tráfico denegado activo en la política implícita",
            expected_value="Logs habilitados para tráfico denegado por defecto",
        )

    # =============================================================================
# CIS 3.1.5 - Ensure Security Profiles (UTM) are Enabled on Accept Policies
# =============================================================================
@register_rule
class EnsureUTMProfilesInAcceptPoliciesRule(BaseRule):
    """CIS Benchmark 3.1.5: Ensure Security Profiles are Enabled on Accept Policies."""

    rule_id = "CIS-3.1.5"
    name = "Enable UTM Security Profiles"
    description = (
        "Garantiza que todas las políticas de firewall de aceptación apliquen "
        "perfiles de inspección de seguridad (Antivirus, IPS, Web Filter) según corresponda."
    )
    category = "Policy and Objects"
    standard = "CIS"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy") or parsed_config.get("firewall policy", {})

        unprotected_policies = []

        if isinstance(policies, dict):
            for policy_id, policy_data in policies.items():
                if isinstance(policy_data, dict):
                    action = policy_data.get("action", "accept")
                    status = policy_data.get("status", "enable")
                    utm_status = policy_data.get("utm-status", "disable")

                    # Verificar si la política está activa, acepta tráfico y no tiene UTM habilitado
                    if action == "accept" and status != "disable" and utm_status != "enable":
                        unprotected_policies.append(str(policy_id))

        if unprotected_policies:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas de aceptación sin perfiles UTM: IDs {', '.join(unprotected_policies)}",
                expected_value="utm-status: enable con perfiles de seguridad asociados",
                remediation_cmd=(
                    "config firewall policy\n"
                    "    edit <ID_POLITICA>\n"
                    "        set utm-status enable\n"
                    "        set av-profile \"default\"\n"
                    "        set ips-sensor \"default\"\n"
                    "        set webfilter-profile \"default\"\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las políticas activas de aceptación tienen perfiles UTM habilitados",
            expected_value="Inspección UTM activa en políticas permitidas",
        )


# =============================================================================
# CIS 3.1.6 - Ensure Deep SSL Inspection is Enabled on Sensitive Policies
# =============================================================================
@register_rule
class EnsureSSLDeepInspectionRule(BaseRule):
    """CIS Benchmark 3.1.6: Ensure Deep SSL Inspection is Enabled on Sensitive Policies."""

    rule_id = "CIS-3.1.6"
    name = "Ensure SSL Deep Inspection"
    description = (
        "Verifica que las políticas con perfiles de seguridad utilicen un perfil de "
        "inspección profunda de SSL/TLS (deep-inspection) para inspeccionar el contenido cifrado."
    )
    category = "Policy and Objects"
    standard = "CIS"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy") or parsed_config.get("firewall policy", {})

        no_deep_inspection = []

        if isinstance(policies, dict):
            for policy_id, policy_data in policies.items():
                if isinstance(policy_data, dict):
                    action = policy_data.get("action", "accept")
                    status = policy_data.get("status", "enable")
                    utm_status = policy_data.get("utm-status", "disable")
                    ssl_ssh = str(policy_data.get("ssl-ssh-profile", "")).lower()

                    if action == "accept" and status != "disable" and utm_status == "enable":
                        # Se evalúa si usa el certificado por defecto o no está en deep-inspection
                        if not ssl_ssh or ssl_ssh in ["no-inspection", "certificate-inspection"]:
                            no_deep_inspection.append(str(policy_id))

        if no_deep_inspection:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas usando inspección superficial o nula: IDs {', '.join(no_deep_inspection)}",
                expected_value="ssl-ssh-profile configurado con 'deep-inspection'",
                remediation_cmd=(
                    "config firewall policy\n"
                    "    edit <ID_POLITICA>\n"
                    "        set ssl-ssh-profile \"deep-inspection\"\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Inspección profunda de SSL activa en las políticas con perfiles UTM",
            expected_value="Perfil deep-inspection asignado correctamente",
        )


# =============================================================================
# CIS 3.1.7 - Ensure Disabled Policies are Reviewed or Removed
# =============================================================================
@register_rule
class AuditDisabledPoliciesRule(BaseRule):
    """CIS Benchmark 3.1.7: Ensure Disabled Policies are Reviewed or Removed."""

    rule_id = "CIS-3.1.7"
    name = "Audit Disabled Policies"
    description = (
        "Detecta políticas de firewall en estado deshabilitado (status disable) "
        "para mantener limpia la tabla de reglas y evitar inconsistencias o fallos operativos."
    )
    category = "Policy and Objects"
    standard = "CIS"
    default_severity = RuleSeverity.LOW

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        policies = parsed_config.get("config firewall policy") or parsed_config.get("firewall policy", {})

        disabled_policies = []

        if isinstance(policies, dict):
            for policy_id, policy_data in policies.items():
                if isinstance(policy_data, dict):
                    status = policy_data.get("status", "enable")
                    if status == "disable":
                        disabled_policies.append(str(policy_id))

        if disabled_policies:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Políticas de firewall deshabilitadas presentes: IDs {', '.join(disabled_policies)}",
                expected_value="Revisar y eliminar políticas deshabilitadas que no sean necesarias",
                remediation_cmd=(
                    "config firewall policy\n"
                    "    delete <ID_POLITICA>\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="No se encontraron políticas deshabilitadas obsoletas",
            expected_value="Tabla de políticas libre de reglas deshabilitadas inútiles",
        )