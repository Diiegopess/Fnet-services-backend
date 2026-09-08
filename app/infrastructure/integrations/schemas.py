# app/integrations/schemas.py

"""
Esquemas Pydantic globales y contratos base para todo el módulo de Integraciones.
"""

from typing import Optional
from pydantic import BaseModel, Field


class BaseConnectivityResult(BaseModel):
    """Contrato base de diagnóstico L7 reutilizable para cualquier conector de red."""
    is_reachable: bool = Field(..., description="Indica si el endpoint o API remota respondió con éxito")
    status_code: Optional[int] = Field(None, description="Código de estado HTTP de la respuesta")
    latency_ms: Optional[float] = Field(None, description="Latencia en milisegundos de la petición")
    error_message: Optional[str] = Field(None, description="Mensaje sanitizado en caso de fallo de red o HTTP")