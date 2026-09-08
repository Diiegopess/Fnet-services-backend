"""Excepciones de Transporte e Integración con Hardware Externo."""

from typing import Any, Optional


class IntegrationError(Exception):
    """Excepción base para fallos de comunicación con plataformas externas."""
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        self.details = details


class IntegrationConnectionError(IntegrationError):
    """Fallo de capa de red/transporte (Timeout, Host inalcanzable, DNS, SSL)."""
    pass


class IntegrationAuthError(IntegrationError):
    """Fallo de autenticación en la API remota (API Token inválido, 401, 403)."""
    pass


class IntegrationHTTPError(IntegrationError):
    """Fallo HTTP retornado por el dispositivo remoto (4xx, 5xx)."""
    def __init__(self, status_code: int, message: str, details: Optional[Any] = None):
        super().__init__(message=f"HTTP {status_code}: {message}", details=details)
        self.status_code = status_code