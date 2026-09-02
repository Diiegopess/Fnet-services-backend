"""
Módulo de Esquemas Pydantic v2 para el Dominio de Auditoría.
"""

from datetime import datetime, timezone
from typing import Any, Dict
import uuid
from pydantic import BaseModel, ConfigDict, Field


class AuditLogCreate(BaseModel):
    """Esquema interno utilizado por los Event Handlers e Interfaces para insertar logs."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    user_id: uuid.UUID | None = None
    ip_address: str = "unknown"
    user_agent: str = "unknown"
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditLogResponse(BaseModel):
    """Esquema público retornado en endpoints administrativos de auditoría."""

    id: uuid.UUID
    event_id: str
    event_type: str
    user_id: uuid.UUID | None = None
    ip_address: str
    user_agent: str
    payload: Dict[str, Any]
    created_at: datetime

    # Si en algún momento añades 'correlation_id' a la BD, lo puedes desmarcar
    correlation_id: str | None = None  

    model_config = ConfigDict(from_attributes=True)