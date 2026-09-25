"""
Catálogo de Permisos del Dominio de Hardening.
"""

from enum import Enum
from app.core.rbac.permissions import register_domain_permissions


class HardeningPermission(str, Enum):
    READ = "hardening:read"
    EXECUTE = "hardening:execute"
    MANAGE = "hardening:manage"


HARDENING_PERMISSION_DESCRIPTIONS: dict[HardeningPermission, str] = {
    HardeningPermission.READ: "Permite consultar perfiles, reglas catálogo y reportes de auditoría de hardening",
    HardeningPermission.EXECUTE: "Permite ejecutar auditorías de hardening sobre dispositivos FortiGate",
    HardeningPermission.MANAGE: "Permite gestionar y crear perfiles/reglas personalizadas de hardening",
}

# Auto-registro dinámico en el Core
register_domain_permissions(HARDENING_PERMISSION_DESCRIPTIONS)