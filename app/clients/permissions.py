"""
Módulo de Permisos RBAC para el Dominio de Clientes.
"""

from enum import Enum
from app.core.rbac.permissions import register_domain_permissions


class ClientPermission(str, Enum):
    """Permisos específicos del dominio de Clientes."""

    CREATE = "clients:create"
    READ = "clients:read"
    UPDATE = "clients:update"
    DELETE = "clients:delete"
    ASSIGN_TECHNICIAN = "clients:assign_technician"


CLIENT_PERMISSION_DESCRIPTIONS: dict[ClientPermission, str] = {
    ClientPermission.CREATE: "Permite registrar nuevos clientes en el sistema",
    ClientPermission.READ: "Permite consultar la información e historial de los clientes",
    ClientPermission.UPDATE: "Permite actualizar la información de clientes existentes",
    ClientPermission.DELETE: "Permite eliminar registros de clientes",
    ClientPermission.ASSIGN_TECHNICIAN: "Permite asignar o reasignar técnicos a un cliente",
}

# Auto-registro dinámico en el Core
register_domain_permissions(CLIENT_PERMISSION_DESCRIPTIONS)