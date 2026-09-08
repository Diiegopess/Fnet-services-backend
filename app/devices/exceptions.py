"""
Excepciones de Dominio exclusivas para Dispositivos Físicos.
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
    def __init__(
        self,
        message: str = "Ya existe un dispositivo registrado con esa dirección host o IP.",
    ):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            message=message,
            error_code="DEVICE_ALREADY_EXISTS",
        )


class DeviceConnectionError(AppException):
    def __init__(
        self,
        message: str = "Error de conexión o comunicación con el dispositivo FortiGate.",
    ):
        super().__init__(
            status_code=status.HTTP_502_BAD_GATEWAY,
            message=message,
            error_code="DEVICE_CONNECTION_ERROR",
        )