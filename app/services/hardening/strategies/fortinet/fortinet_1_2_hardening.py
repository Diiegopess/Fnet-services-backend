from typing import Any, Dict
from app.services.hardening.models import FindingStatus, RuleSeverity
from app.services.hardening.strategies.base import BaseRule, RuleResult
from app.services.hardening.strategies.registry import register_rule


# =============================================================================
# FORTI-005 - Enable Private Data Encryption
# =============================================================================
@register_rule
class PrivateDataEncryptionRule(BaseRule):
    """Fortinet Best Practices: Habilitar el cifrado de datos privados en la configuración."""

    rule_id = "FORTI-005"
    name = "Enable Private Data Encryption"
    description = (
        "Cifra las contraseñas y claves privadas almacenadas en la configuración local utilizando una "
        "clave personalizada definida por el administrador en lugar de la clave predeterminada."
    )
    category = "Hardening"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        pde = system_global.get("private-data-encryption", "disable")

        if pde == "enable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Cifrado de datos privados (private-data-encryption) habilitado",
                expected_value="private-data-encryption enable",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value="Cifrado de datos privados deshabilitado (las claves usan cifrado por defecto)",
            expected_value="private-data-encryption enable",
            remediation_cmd=(
                "config system global\n"
                "    set private-data-encryption enable\n"
                "end"
            ),
        )


# =============================================================================
# FORTI-006 - Enforce Strong Cryptography
# =============================================================================
@register_rule
class StrongCryptoRule(BaseRule):
    """Fortinet Best Practices: Habilitar cifrados criptográficos fuertes."""

    rule_id = "FORTI-006"
    name = "Enforce Strong Cryptography"
    description = (
        "Asegura que el parámetro 'strong-crypto' esté habilitado para forzar niveles de encriptación "
        "fuertes y deshabilitar algoritmos débiles o obsoletos en el sistema."
    )
    category = "Hardening"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.HIGH

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        strong_crypto = system_global.get("strong-crypto", "enable")

        if strong_crypto == "enable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Criptografía fuerte (strong-crypto) habilitada",
                expected_value="strong-crypto enable",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value="Criptografía fuerte deshabilitada (permite algoritmos débiles)",
            expected_value="strong-crypto enable",
            remediation_cmd="config system global\n    set strong-crypto enable\nend",
        )


# =============================================================================
# FORTI-007 - Disable Static Key SSL Ciphers
# =============================================================================
@register_rule
class DisableStaticKeyCiphersRule(BaseRule):
    """Fortinet Best Practices: Deshabilitar suites de cifrado SSL de clave estática."""

    rule_id = "FORTI-007"
    name = "Disable Static Key Ciphers"
    description = (
        "Deshabilita los cifrados de clave estática SSL/TLS para mitigar riesgos de interceptación "
        "y garantizar Perfect Forward Secrecy (PFS)."
    )
    category = "Hardening"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        system_global = parsed_config.get("config system global", {})

        if not system_global:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        static_key_ciphers = system_global.get("ssl-static-key-ciphers", "disable")

        if static_key_ciphers == "disable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Cifrados SSL de clave estática deshabilitados",
                expected_value="ssl-static-key-ciphers disable",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value="Cifrados SSL de clave estática permitidos",
            expected_value="ssl-static-key-ciphers disable",
            remediation_cmd="config system global\n    set ssl-static-key-ciphers disable\nend",
        )


# =============================================================================
# FORTI-008 - Disable Auto USB Firmware/Config Installation
# =============================================================================
@register_rule
class DisableUSBAutoInstallRule(BaseRule):
    """Fortinet Best Practices: Deshabilitar instalación automática desde USB."""

    rule_id = "FORTI-008"
    name = "Disable USB Auto-Installation"
    description = (
        "Previene que personal no autorizado actualice el firmware o cargue archivos de configuración "
        "mediante la inserción de un dispositivo de almacenamiento USB."
    )
    category = "Physical Security & Hardening"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        auto_install = parsed_config.get("config system auto-install", {})

        if not auto_install:
            # Por defecto en FortiOS están deshabilitados, pero la regla valida el estado explícito o por defecto
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Instalación por USB configurada por defecto (deshabilitada)",
                expected_value="auto-install-config y auto-install-image deshabilitados",
            )

        config_status = auto_install.get("auto-install-config", "disable")
        image_status = auto_install.get("auto-install-image", "disable")

        if config_status == "disable" and image_status == "disable":
            return RuleResult(
                status=FindingStatus.PASSED,
                current_value="Instalación automática desde USB deshabilitada",
                expected_value="auto-install-config disable y auto-install-image disable",
            )

        return RuleResult(
            status=FindingStatus.FAILED,
            current_value=f"Instalación USB activa (config: {config_status}, image: {image_status})",
            expected_value="Ambas opciones deshabilitadas",
            remediation_cmd=(
                "config system auto-install\n"
                "    set auto-install-config disable\n"
                "    set auto-install-image disable\n"
                "end"
            ),
        )


# =============================================================================
# FORTI-009 - Verify PBKDF2 Password Hashing
# =============================================================================
@register_rule
class PBKDF2HashingRule(BaseRule):
    """Fortinet Best Practices: Verificar uso de hashing PBKDF2 en usuarios administradores."""

    rule_id = "FORTI-009"
    name = "Enforce PBKDF2 Password Hashing"
    description = (
        "FortiOS 7.4.8+ reemplaza SHA256 por PBKDF2 para el almacenamiento de contraseñas de administradores. "
        "Identifica si existen cuentas usando esquemas de hash heredados (SHA256 con prefijo SH2 en lugar de PB2)."
    )
    category = "Administrative Settings"
    standard = "FORTINET"
    standard_version = "v7.4"
    default_severity = RuleSeverity.MEDIUM

    def evaluate(self, parsed_config: Dict[str, Any]) -> RuleResult:
        admins = parsed_config.get("config system admin", {})

        if not admins:
            return RuleResult(status=FindingStatus.NOT_APPLICABLE)

        legacy_hash_users = []

        for admin_name, admin_data in admins.items():
            pwd = admin_data.get("password", "")
            # FortiOS almacena los passwords en formato "ENC PB2..." o "ENC SH2..."
            if "SH2" in pwd:
                legacy_hash_users.append(admin_name)

        if legacy_hash_users:
            return RuleResult(
                status=FindingStatus.FAILED,
                current_value=f"Administradores con contraseñas en formato SHA256 heredado: {', '.join(legacy_hash_users)}",
                expected_value="Todos los hashes de administración codificados con algoritmo PBKDF2 (prefijo PB2)",
                remediation_cmd=(
                    "# Solicitar inicio de sesión a cada usuario o restablecer su contraseña manualmente:\n"
                    "config system admin\n"
                    "    edit <admin_user>\n"
                    "        set password <new_password>\n"
                    "    next\n"
                    "end"
                ),
            )

        return RuleResult(
            status=FindingStatus.PASSED,
            current_value="Todas las cuentas de administración verificadas utilizan hashing PBKDF2 (PB2)",
            expected_value="Hashes con PBKDF2 (PB2)",
        )