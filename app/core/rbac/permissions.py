"""
Definición de permisos granulares para los módulos base: Auth, Users y Audit.
"""
from enum import Enum


class PermissionEnum(str, Enum):
    # Dominio: Usuarios
    USERS_READ = "users:read"
    USERS_CREATE = "users:create"
    USERS_UPDATE = "users:update"
    USERS_DELETE = "users:delete"
    USERS_ASSIGN_ROLE = "users:assign_role"

    # Dominio: Auditoría
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"