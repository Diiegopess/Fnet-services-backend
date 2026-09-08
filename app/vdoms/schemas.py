import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class VDOMBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Nombre del VDOM en FortiOS (ej. root, DMZ)")
    is_root: bool = Field(default=False, description="Indica si es el VDOM principal")
    is_active: bool = Field(default=True, description="Estado operativo del VDOM en la plataforma")


class VDOMCreate(VDOMBase):
    device_id: uuid.UUID = Field(..., description="ID del chasis físico registrado")
    client_id: Optional[uuid.UUID] = Field(None, description="ID del cliente asignado (opcional al crear)")


class VDOMUpdate(BaseModel):
    client_id: Optional[uuid.UUID] = Field(None, description="Reasignar a otro cliente o desvincular (None)")
    is_active: Optional[bool] = Field(None, description="Activar o desactivar el VDOM")


class VDOMResponse(VDOMBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    client_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime


class VDOMContext(BaseModel):
    """Contexto validado de un VDOM para inyección de dependencias en endpoints."""
    vdom_id: uuid.UUID
    vdom_name: str
    is_root: bool
    device_id: uuid.UUID
    client_id: Optional[uuid.UUID] = None

    model_config = ConfigDict(frozen=True)


class VDOMSyncItem(BaseModel):
    """Item detectado durante el auto-discovery en el dispositivo."""
    name: str
    is_root: bool = False


class VDOMSyncResult(BaseModel):
    """Resultado del escaneo e importación de VDOMs de un dispositivo."""
    device_id: uuid.UUID
    total_found: int
    new_registered: int
    existing_unaltered: int