"""
Módulo de Permisos RBAC para el Dominio de Autenticación.
"""

from enum import Enum
from app.core.rbac.permissions import register_domain_permissions


class AuthPermission(str, Enum):
    """Permisos específicos para operaciones avanzadas de autenticación."""

    REVOKE_TOKEN = "auth:revoke_token"
    MANAGE_SESSIONS = "auth:manage_sessions"
    READ_AUDIT_LOGS = "auth:read_audit_logs"


AUTH_PERMISSION_DESCRIPTIONS: dict[AuthPermission, str] = {
    AuthPermission.REVOKE_TOKEN: "Permite revocar tokens de acceso e inactivar sesiones de usuarios",
    AuthPermission.MANAGE_SESSIONS: "Permite gestionar y cerrar sesiones activas globalmente",
    AuthPermission.READ_AUDIT_LOGS: "Permite consultar los registros de auditoría de autenticación e inicios de sesión",
}

# Auto-registro en el Core
register_domain_permissions(AUTH_PERMISSION_DESCRIPTIONS)