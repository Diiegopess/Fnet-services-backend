import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.infrastructure.db.database import Base


# --- ENUMS DEL DOMINIO ---

class ProfileType(str, enum.Enum):
    SYSTEM = "SYSTEM"  # Plantilla de fábrica (CIS Benchmark, Fortinet BP)
    CUSTOM = "CUSTOM"  # Perfil clonado/modificado por el técnico


class ExecutionType(str, enum.Enum):
    FULL_STANDARD = "FULL_STANDARD"
    ASSIGNED_PROFILE = "ASSIGNED_PROFILE"
    CUSTOM_ADHOC = "CUSTOM_ADHOC"


class FindingStatus(str, enum.Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"  # Eliminamos EXEMPT al no haber excepciones formales


class RuleSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# --- TABLA INTERMEDIA (M:M Perfiles <-> Reglas) ---

profile_rules_association = Table(
    "hardening_profile_rules",
    Base.metadata,
    Column("profile_id", UUID(as_uuid=True), ForeignKey("hardening_profiles.id", ondelete="CASCADE"), primary_key=True),
    Column("rule_id", String(50), ForeignKey("hardening_rule_catalog.id", ondelete="CASCADE"), primary_key=True),
)


# --- TABLAS PRINCIPALES ---

class RuleCatalog(Base):
    """Catálogo Maestro de Reglas de Hardening."""

    __tablename__ = "hardening_rule_catalog"

    id = Column(String(50), primary_key=True)  # Ej: 'CIS-1.1'
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=False)
    standard = Column(String(50), nullable=False)
    default_severity = Column(Enum(RuleSeverity), default=RuleSeverity.MEDIUM, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class HardeningProfile(Base):
    """
    Perfiles / Plantillas de Evaluación.
    Si el técnico quiere quitar checks, clona un perfil SYSTEM a uno CUSTOM
    y quita la asociación de la regla en 'hardening_profile_rules'.
    """

    __tablename__ = "hardening_profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(150), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    profile_type = Column(Enum(ProfileType), default=ProfileType.CUSTOM, nullable=False)
    
    # Campo requerido por HardeningProfileResponse
    is_active = Column(Boolean, default=True, nullable=False)

    created_by = Column(UUID(as_uuid=True), nullable=True)  # Técnico que creó la plantilla personalizada
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Reglas asociadas activamente a este perfil
    rules = relationship("RuleCatalog", secondary=profile_rules_association, backref="profiles")


class AuditReport(Base):
    """Cabecera del Reporte de Auditoría de Hardening."""

    __tablename__ = "hardening_audit_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), nullable=False)  # Removida FK directa si genera choque en init_db
    vdom_id = Column(UUID(as_uuid=True), nullable=True)     # Se mantiene como UUID para ligar al VDOM
    execution_type = Column(Enum(ExecutionType), nullable=False)
    profile_id = Column(UUID(as_uuid=True), ForeignKey("hardening_profiles.id", ondelete="SET NULL"), nullable=True)
    
    score = Column(Float, nullable=False)
    total_passed = Column(Integer, default=0, nullable=False)
    total_failed = Column(Integer, default=0, nullable=False)
    total_not_applicable = Column(Integer, default=0, nullable=False)

    executed_by = Column(UUID(as_uuid=True), nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    findings = relationship("AuditFinding", back_populates="report", cascade="all, delete-orphan")


class AuditFinding(Base):
    """Detalle de cada regla evaluada en un reporte específico."""

    __tablename__ = "hardening_audit_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = Column(UUID(as_uuid=True), ForeignKey("hardening_audit_reports.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(50), ForeignKey("hardening_rule_catalog.id"), nullable=False)

    status = Column(Enum(FindingStatus), nullable=False)
    severity = Column(Enum(RuleSeverity), nullable=False)
    current_value = Column(Text, nullable=True)
    expected_value = Column(Text, nullable=True)
    remediation_cmd = Column(Text, nullable=True)

    report = relationship("AuditReport", back_populates="findings")