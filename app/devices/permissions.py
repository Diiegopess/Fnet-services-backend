"""
Catálogo de Permisos del Dominio de Dispositivos (FortiGate Devices).
"""

from enum import Enum
from app.core.rbac.permissions import register_domain_permissions


class DevicePermission(str, Enum):
    READ = "devices:read"
    CREATE = "devices:create"
    UPDATE = "devices:update"
    DELETE = "devices:delete"
    TEST_CONNECTION = "devices:test_connection"


DEVICE_PERMISSION_DESCRIPTIONS: dict[DevicePermission, str] = {
    DevicePermission.READ: "Permite listar y visualizar detalles de los dispositivos registrados",
    DevicePermission.CREATE: "Permite registrar nuevos chasis FortiGate en la plataforma",
    DevicePermission.UPDATE: "Permite actualizar parámetros de conexión de un dispositivo",
    DevicePermission.DELETE: "Permite eliminar un dispositivo registrado",
    DevicePermission.TEST_CONNECTION: "Permite probar conectividad y credenciales contra un equipo FortiGate",
}

# Auto-registro en el registro central del Core
register_domain_permissions(DEVICE_PERMISSION_DESCRIPTIONS)