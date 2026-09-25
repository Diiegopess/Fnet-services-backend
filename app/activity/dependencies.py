"""
Dependencias de FastAPI e Inyección de Contexto Autorizado para Activity.
"""

from app.activity.permissions import ActivityPermission
from app.auth.api import require_permission


def require_activity_permission(permission: ActivityPermission):
    """Dependency helper para validar permisos del dominio de Activity."""
    return require_permission(permission.value)