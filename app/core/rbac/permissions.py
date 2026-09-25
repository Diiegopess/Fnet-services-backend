"""
Registro central e independiente de Permisos del Sistema (RBAC).
El Core NO conoce los subdominios; los subdominios o el bootstrap registran sus permisos.
"""

from typing import Dict

# Diccionario interno en memoria que actuará como Registro Central
_REGISTERED_SYSTEM_PERMISSIONS: Dict[str, str] = {}


def register_domain_permissions(permissions_dict: dict) -> None:
    """
    Permite a cualquier subdominio registrar su mapa de permisos {Enum/str: descripcion}.
    """
    for perm, desc in permissions_dict.items():
        key = perm.value if hasattr(perm, "value") else str(perm)
        _REGISTERED_SYSTEM_PERMISSIONS[key] = desc


def load_all_domain_permissions() -> None:
    """
    Importa bajo demanda los permisos de cada subdominio.
    Útil para scripts de administración, CLI y seeders donde Uvicorn no ha cargado los routers HTTP.
    """
    import app.activity.permissions  # noqa: F401
    import app.auth.permissions  # noqa: F401
    import app.clients.permissions  # noqa: F401
    import app.devices.permissions  # noqa: F401
    import app.services.hardening.permissions  # noqa: F401
    import app.users.permissions  # noqa: F401
    import app.vdoms.permissions  # noqa: F401


def get_all_system_permissions() -> Dict[str, str]:
    """
    Retorna la totalidad de permisos registrados dinámicamente en el sistema.
    Si el registro está vacío (ej. fuera del ciclo HTTP de FastAPI), fuerza la carga del catálogo.
    """
    if not _REGISTERED_SYSTEM_PERMISSIONS:
        load_all_domain_permissions()

    return _REGISTERED_SYSTEM_PERMISSIONS.copy()