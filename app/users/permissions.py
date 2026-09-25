"""
Módulo de Permisos RBAC para el Dominio de Usuarios y Roles.
"""

from enum import Enum
from app.core.rbac.permissions import register_domain_permissions


class UserPermission(str, Enum):
    """Permisos específicos del dominio de Usuarios y Roles."""

    READ = "users:read"
    CREATE = "users:create"
    UPDATE = "users:update"
    DELETE = "users:delete"
    ASSIGN_ROLE = "users:assign_role"


USER_PERMISSION_DESCRIPTIONS: dict[UserPermission, str] = {
    UserPermission.READ: "Permite listar y consultar el detalle de usuarios y sus roles asignados",
    UserPermission.CREATE: "Permite registrar nuevos usuarios en el sistema",
    UserPermission.UPDATE: "Permite actualizar la información de usuarios existentes",
    UserPermission.DELETE: "Permite desactivar o eliminar cuentas de usuario",
    UserPermission.ASSIGN_ROLE: "Permite asignar o modificar los roles y permisos concedidos a un usuario",
}

# Auto-registro dinámico en el Core
register_domain_permissions(USER_PERMISSION_DESCRIPTIONS)