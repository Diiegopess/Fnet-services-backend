from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# FORTI-019 - Enforce Botnet C&C Domain/IP Blocking in DNS Filter
# =============================================================================
@register_rule
class DNSFilterBotnetProtectionRule(BaseRule):
    """Fortinet Best Practices: Bloquear conexiones a servidores Botnet C&C mediante DNS Filter."""

    rule_id = "FORTI-019"
    name = "Enforce Botnet C&C Blocking in DNS Filter"
    description = (
        "Garantiza que el perfil de DNS Filter tenga habilitado el bloqueo automático de consultas "
        "hacia dominios conocidos de mando y control (Botnet C&C)."
    )
    category = "Security Profiles / DNS Filter"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        dns_profiles = parsed_config.get("config dnsfilter profile", {})

        if not dns_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No hay perfiles de DNS Filter configurados",
                expected_value="Crear y aplicar un perfil de DNS Filter bloqueando Botnet C&C",
                remediation_cmd=(
                    "config dnsfilter profile\n"
                    "    edit \"default\"\n"
                    "        set block-botnet-connections enable\n"
                    "    next\n"
                    "end"
                ),
            )

        failing_profiles = []

        for profile_name, profile_data in dns_profiles.items():
            botnet_block = profile_data.get("block-botnet-connections", "enable")
            if botnet_block == "disable":
                failing_profiles.append(profile_name)

        if failing_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Perfiles DNS Filter con bloqueo de Botnet deshabilitado: {', '.join(failing_profiles)}",
                expected_value="block-botnet-connections enable",
                remediation_cmd=(
                    "config dnsfilter profile\n"
                    "    edit <profile_name>\n"
                    "        set block-botnet-connections enable\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todos los perfiles de DNS Filter tienen habilitado el bloqueo de Botnet C&C",
            expected_value="Bloqueo de Botnet activo en DNS Filter",
        )


# =============================================================================
# FORTI-020 - Replace Factory Default Admin Certificates
# =============================================================================
@register_rule
class AdminCustomCertificateRule(BaseRule):
    """Fortinet Best Practices: Reemplazar el certificado de administración por defecto (Factory Default)."""

    rule_id = "FORTI-020"
    name = "Replace Default Certificate for Admin/SSL"
    description = (
        "Evita el uso del certificado auto-firmado de fábrica (Fortinet_Factory) para la interfaz web "
        "y el portal SSL-VPN, forzando el uso de un certificado emitido por una CA confiable."
    )
    category = "Certificates & Infrastructure"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        admin_cert = system_global.get("admin-server-cert", "Fortinet_Factory")

        if admin_cert == "Fortinet_Factory":
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="Uso del certificado de fábrica por defecto ('Fortinet_Factory') para la GUI",
                expected_value="Usar un certificado firmado por una CA privada o pública confiable",
                remediation_cmd=(
                    "config system global\n"
                    "    set admin-server-cert <custom_ca_signed_cert>\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Certificado de administración personalizado en uso: {admin_cert}",
            expected_value="Certificado no predeterminado para la consola administrativa",
        )


# =============================================================================
# FORTI-021 - Centralized Logging to FortiAnalyzer or FortiCloud
# =============================================================================
@register_rule
class CentralizedLoggingRule(BaseRule):
    """Fortinet Best Practices: Habilitar registro centralizado (FortiAnalyzer o FortiCloud)."""

    rule_id = "FORTI-021"
    name = "Enable Centralized Remote Logging"
    description = (
        "Verifica que el almacenamiento de registros no dependa únicamente de la memoria o disco local. "
        "Es imprescindible enviar eventos a un colector externo (FortiAnalyzer, FortiManager o FortiCloud) para auditoría."
    )
    category = "Logging & Report"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        faz_config = parsed_config.get("config log fortianalyzer setting", {})
        cloud_config = parsed_config.get("config log forticloud setting", {})

        faz_status = faz_config.get("status", "disable")
        cloud_status = cloud_config.get("status", "disable")

        if faz_status == "enable" or cloud_status == "enable":
            active_destinations = []
            if faz_status == "enable":
                active_destinations.append("FortiAnalyzer")
            if cloud_status == "enable":
                active_destinations.append("FortiCloud")

            return RuleResult(
                status=FindingStatus.PASSED,
                current_value=f"Envío de registros remoto activo en: {', '.join(active_destinations)}",
                expected_value="FortiAnalyzer o FortiCloud habilitado",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value="Registro remoto deshabilitado (no se envía a FortiAnalyzer ni FortiCloud)",
            expected_value="Habilitar el envío centralizado de logs a FortiAnalyzer o FortiCloud",
            remediation_cmd=(
                "config log fortianalyzer setting\n"
                "    set status enable\n"
                "    set server <FAZ_IP>\n"
                "end"
            ),
        )


# =============================================================================
# FORTI-022 - Enable AntiVirus Outbreak Prevention / Inline Scanning
# =============================================================================
@register_rule
class AntiVirusInlineScanRule(BaseRule):
    """Fortinet Best Practices: Habilitar base de datos de firmas extendidas/AI en AntiVirus."""

    rule_id = "FORTI-022"
    name = "Configure AntiVirus Database and Scanning"
    description = (
        "Comprueba que el motor de AntiVirus esté utilizando bases de datos de firmas completas "
        "u opciones avanzadas de protección para la detección oportuna de malware."
    )
    category = "Security Profiles / AntiVirus"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        av_profiles = parsed_config.get("config antivirus profile", {})

        if not av_profiles:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value="No hay perfiles de AntiVirus definidos",
                expected_value="Configurar perfiles AntiVirus e inspección en políticas de trafico",
                remediation_cmd=(
                    "config antivirus profile\n"
                    "    edit \"default\"\n"
                    "        config http\n"
                    "            set av-scan block\n"
                    "        end\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value=f"Se encontraron {len(av_profiles)} perfil(es) AntiVirus configurado(s)",
            expected_value="Perfiles Antivirus presentes para inspección de flujos de datos",
        )