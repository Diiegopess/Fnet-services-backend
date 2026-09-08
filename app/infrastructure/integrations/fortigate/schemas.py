"""
Esquemas Pydantic específicos para las respuestas y modelos de datos de FortiGate / FortiOS.
"""

from typing import Optional
from pydantic import BaseModel, Field

# Importamos el contrato base correcto definido en app/infrastructure/integrations/schemas.py
from app.infrastructure.integrations.schemas import BaseConnectivityResult


class FortiGateConnectivityResult(BaseConnectivityResult):
    """
    Resultado técnico del sondeo L7 contra la REST API de FortiOS.
    Hereda los campos básicos de alcance/latencia de BaseConnectivityResult.
    """
    serial_number: Optional[str] = Field(
        None, description="Número de serie extraído del chasis/VM FortiGate"
    )
    detected_version: Optional[str] = Field(
        None, description="Versión principal o build de FortiOS detectado (ej. 7.2.4)"
    )
    vdom_mode: Optional[str] = Field(
        None, description="Modo de VDOM configurado en el equipo (multi-vdom, split-vdom, no-vdom)"
    )


class FortiGateSystemStatus(BaseModel):
    """
    Esquema simplificado para mapear el payload retornado por:
    /api/v2/monitor/system/status
    """
    serial: str = Field(..., description="Número de serie del equipo")
    version: str = Field(..., description="Versión de FortiOS")
    hostname: str = Field(..., description="Hostname configurado en el equipo")
    vdom_mode: Optional[str] = Field(None, description="Modo VDOM operativo")