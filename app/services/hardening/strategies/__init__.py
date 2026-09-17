"""
Módulo de inicialización para la carga automática de estrategias y reglas de Hardening.
Al importar este paquete, se ejecutan los decoradores de registro de cada regla en el RuleRegistry.
"""

from app.services.hardening.strategies.cis import cis_1_1_network, cis_2_1_system_settings, cis_2_2_administrator_accounts, cis_4_1_security_profiles, cis_5_1_logging_and_reporting, cis_6_1_high_availability
from app.services.hardening.strategies.fortinet import system_rules
from app.services.hardening.strategies.gamma import admin_rules


# Exportamos las reglas para garantizar la disponibilidad global
__all__ = [
    "cis_1_1_network",
    "cis_2_1_system_settings",
    "cis_2_2_administrator_accounts",
    "cis_2_3_network_services",
    "cis_3_1_policy_and_objetcs",
    "cis_4_1_security_profiles",
    "cis_5_1_logging_and_reporting",
    "cis_6_1_high_availability",
    "system_rules",
    "admin_rules",
]