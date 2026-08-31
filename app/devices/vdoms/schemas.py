"""
Esquemas Pydantic para el Subdominio de VDOMs (Particiones Lógicas).
"""

import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class VDOMBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Nombre del VDOM en FortiOS (ej. root, DMZ)")
    is_root: bool = Field(default=False, description="Indica si es el VDOM principal o modo standalone")
    is_active: bool = Field(default=True, description="Estado operativo del VDOM")


class VDOMCreate(VDOMBase):
    device_id: uuid.UUID = Field(..., description="ID del chasis físico FortiGate")
    client_id: uuid.UUID = Field(..., description="ID del cliente al que pertenece este VDOM")


class VDOMUpdate(BaseModel):
    client_id: Optional[uuid.UUID] = Field(None, description="Reasignar a otro cliente")
    is_active: Optional[bool] = None


class VDOMResponse(VDOMBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    client_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class VDOMSyncItem(BaseModel):
    """Item detectado durante el auto-discovery en el firewall."""
    name: str
    is_root: bool = False


class VDOMSyncResult(BaseModel):
    """Resultado del escaneo de VDOMs en un chasis."""
    device_id: uuid.UUID
    total_found: int
    new_registered: int
    existing_unaltered: int