"""
Esquemas Pydantic para el Dominio de Dispositivos (Hardware / Chasis Fortinet).
"""

import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.devices.vdoms.schemas import VDOMResponse

from enum import Enum

class FortiOSVersion(str, Enum):
    V6_4 = "6.4"
    V7_0 = "7.0"
    V7_2 = "7.2"
    V7_4 = "7.4"
    MOCK = "mock"  # <-- Para pruebas locales / desarrollo

class DeviceBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=150, description="Identificador amigable del equipo")
    host: str = Field(..., description="Dirección IP o FQDN de gestión HTTPS")
    port: int = Field(default=443, ge=1, le=65535, description="Puerto de gestión de la API")
    fortios_version: str = Field(default="7.2", description="Versión principal de FortiOS (7.0, 7.2, 7.4)")
    is_active: bool = Field(default=True, description="Habilita/Deshabilita consultas al equipo")


class DeviceCreate(DeviceBase):
    api_token: str = Field(..., min_length=10, description="Token REST API generado en FortiOS")
    has_vdom_enabled: bool = Field(default=False, description="True si tiene múltiples VDOMs activos")
    # Si no tiene VDOMs habilitados, se asocia el equipo a un cliente por defecto
    default_client_id: Optional[uuid.UUID] = Field(
        None, 
        description="Cliente propietario si opera en modo root/standalone"
    )


class DeviceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=150)
    host: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    api_token: Optional[str] = Field(None, min_length=10)
    fortios_version: Optional[str] = None
    has_vdom_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


class DeviceResponse(DeviceBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    serial_number: Optional[str] = None
    has_vdom_enabled: bool
    vdoms: List[VDOMResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ConnectivityCheckResult(BaseModel):
    """Resultado de la prueba de conexión contra el FortiGate."""
    is_reachable: bool
    status_code: Optional[int] = None
    serial_number: Optional[str] = None
    detected_version: Optional[str] = None
    vdom_mode: Optional[str] = None
    latency_ms: Optional[float] = None
    error_message: Optional[str] = None

class DeviceTestConnectionRequest(BaseModel):
    """Payload para test de conectividad previo al registro."""
    host: str = Field(..., description="IP o FQDN del FortiGate")
    port: int = Field(default=443, ge=1, le=65535)
    api_token: str = Field(..., min_length=10, description="Token REST API")