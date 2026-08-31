"""
Esquemas Pydantic para el Dominio de Clientes.
"""

import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class ClientBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, description="Nombre o razón social")
    tax_id: Optional[str] = Field(None, max_length=50, description="Identificación fiscal / NIT / RFC")
    contact_email: Optional[EmailStr] = Field(None, description="Correo electrónico principal")
    contact_phone: Optional[str] = Field(None, max_length=50, description="Teléfono de contacto")
    address: Optional[str] = Field(None, description="Dirección física")
    is_active: bool = Field(True, description="Estado operativo del cliente")


class ClientCreate(ClientBase):
    pass


class ClientUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    tax_id: Optional[str] = Field(None, max_length=50)
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = Field(None, max_length=50)
    address: Optional[str] = None
    is_active: Optional[bool] = None


class TechnicianAssignmentSchema(BaseModel):
    technician_ids: List[uuid.UUID] = Field(..., description="Lista de UUIDs de usuarios asignados")


class AssignedTechnicianResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: Optional[str] = None


class ClientResponse(ClientBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assigned_technicians: List[AssignedTechnicianResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime