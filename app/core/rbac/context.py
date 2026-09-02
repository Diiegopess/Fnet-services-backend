"""
Contexto de Identidad y Autorización para capas de transporte y eventos.
"""

import uuid
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr


class AuthenticatedUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool = True
    is_superuser: bool = False
    permissions: set[str] = set()