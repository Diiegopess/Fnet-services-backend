"""
Modelo SQLAlchemy para el subdominio de Dispositivos (FortiGate Hardware).
"""

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.db.database import Base


class FortigateDevice(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    port: Mapped[int] = mapped_column(Integer, default=443, nullable=False)
    
    # Credenciales cifradas
    encrypted_api_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Metadatos del dispositivo
    fortios_version: Mapped[str] = mapped_column(String(20), default="7.2", nullable=False)
    serial_number: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)
    has_vdom_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Referencia desacoplada (ID) al cliente asignado (standalone)
    client_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )