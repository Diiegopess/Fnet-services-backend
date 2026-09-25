"""
Catálogo de Permisos del Dominio de VDOMs.
"""

from enum import Enum
from app.core.rbac.permissions import register_domain_permissions


class VDOMPermission(str, Enum):
    READ = "vdoms:read"
    CREATE = "vdoms:create"
    UPDATE = "vdoms:update"
    DELETE = "vdoms:delete"


VDOM_PERMISSION_DESCRIPTIONS: dict[VDOMPermission, str] = {
    VDOMPermission.READ: "Permite consultar los VDOMs y su detalle",
    VDOMPermission.CREATE: "Permite crear y sincronizar particiones VDOM",
    VDOMPermission.UPDATE: "Permite actualizar configuraciones o reasignar clientes a VDOMs",
    VDOMPermission.DELETE: "Permite eliminar particiones VDOM de la plataforma",
}

# Auto-registro dinámico en el Core
register_domain_permissions(VDOM_PERMISSION_DESCRIPTIONS)