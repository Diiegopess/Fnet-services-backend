"""
Catálogo de Permisos del Dominio de Activity.
"""

from enum import Enum
from app.core.rbac.permissions import register_domain_permissions


class ActivityPermission(str, Enum):
    READ = "activity:read"
    EXPORT = "activity:export"


ACTIVITY_PERMISSION_DESCRIPTIONS: dict[ActivityPermission, str] = {
    ActivityPermission.READ: "Permite listar y consultar los logs de actividad e historial del sistema",
    ActivityPermission.EXPORT: "Permite exportar reportes de actividad e historial de auditoría",
}

# Auto-registro en el registro central del Core al cargar la clase
register_domain_permissions(ACTIVITY_PERMISSION_DESCRIPTIONS)