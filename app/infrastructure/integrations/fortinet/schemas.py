# app/infrastructure/integrations/fortinetIntegrations/schemas.py

from typing import Optional
from pydantic import Field
from app.infrastructure.integrations.schemas import BaseConnectivityResult


class FortiGateConnectivityResult(BaseConnectivityResult):
    """Resultado técnico del sondeo L7 contra la REST API de FortiOS."""

    serial_number: Optional[str] = Field(
        None, description="Número de serie extraído del chasis/VM FortiGate"
    )
    detected_version: Optional[str] = Field(
        None, description="Versión principal o build de FortiOS detectado (ej. 7.2.4)"
    )
    vdom_mode: Optional[str] = Field(
        None, description="Modo de VDOM configurado en el equipo"
    )