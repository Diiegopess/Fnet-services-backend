import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class EventMetadata(BaseModel):
    """Metadatos de auditoría, red y actor asociados al evento."""
    actor_id: Optional[str] = None
    actor_email: Optional[str] = None
    ip_address: Optional[str] = "unknown"
    user_agent: Optional[str] = "unknown"
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class DomainEvent(BaseModel):
    """Estructura base inmutable para cualquier evento del sistema."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str  # Ej: 'auth.user_registered', 'clients.client_created'
    occurred_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: EventMetadata = Field(default_factory=EventMetadata)
    payload: Dict[str, Any] = Field(default_factory=dict)