"""
Excepciones de Dominio para Dispositivos y VDOMs.
"""

from fastapi import status
from app.core.exceptions import AppException


class DeviceNotFoundError(AppException):
    def __init__(self, message: str = "Dispositivo FortiGate no encontrado."):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            message=message,
            error_code="DEVICE_NOT_FOUND",
        )


class DeviceAlreadyExistsError(AppException):
    def __init__(self, message: str = "Ya existe un dispositivo registrado con esa dirección host o IP."):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            message=message,
            error_code="DEVICE_ALREADY_EXISTS",
        )


class VDOMNotFoundError(AppException):
    def __init__(self, message: str = "VDOM no encontrado en este dispositivo."):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            message=message,
            error_code="VDOM_NOT_FOUND",
        )


class VDOMAlreadyExistsError(AppException):
    def __init__(self, message: str = "Ya existe un VDOM con ese nombre en el dispositivo."):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            message=message,
            error_code="VDOM_ALREADY_EXISTS",
        )


class VDOMAccessDeniedError(AppException):
    def __init__(self, message: str = "No tienes asignación ni permisos sobre el cliente propietario de este VDOM."):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            message=message,
            error_code="VDOM_ACCESS_DENIED",
        )