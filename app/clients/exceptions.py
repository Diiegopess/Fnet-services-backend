"""
Excepciones de Dominio para el Módulo de Clientes.
"""

from fastapi import status
from app.core.exceptions import AppException


class ClientNotFoundError(AppException):
    def __init__(self, message: str = "Cliente no encontrado."):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            message=message,
            error_code="CLIENT_NOT_FOUND",
        )


class ClientAlreadyExistsError(AppException):
    def __init__(self, message: str = "Ya existe un cliente con ese nombre o identificación fiscal."):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            message=message,
            error_code="CLIENT_ALREADY_EXISTS",
        )


class InvalidTechnicianAssignmentError(AppException):
    def __init__(self, message: str = "Uno o más identificadores de técnicos no son válidos o están inactivos."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message=message,
            error_code="INVALID_TECHNICIAN_ASSIGNMENT",
        )