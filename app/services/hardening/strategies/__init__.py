"""
Módulo de inicialización para la carga automática de estrategias y reglas de Hardening.
Al importar este paquete, se ejecutan los decoradores de registro de cada regla en el RuleRegistry.
"""

from app.services.hardening.strategies.cis import cis_1_network
from app.services.hardening.strategies.fortinet import system_rules
from app.services.hardening.strategies.gamma import admin_rules


# Exportamos las reglas para garantizar la disponibilidad global
__all__ = [
    "cis_1_network",
    "system_rules",
    "admin_rules",
]