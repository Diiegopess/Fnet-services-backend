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
    SYSTEM = "SYSTEM"
    CUSTOM = "CUSTOM"


class ExecutionType(str, enum.Enum):
    FULL_STANDARD = "FULL_STANDARD"
    ASSIGNED_PROFILE = "ASSIGNED_PROFILE"
    CUSTOM_ADHOC = "CUSTOM_ADHOC"


class FindingStatus(str, enum.Enum):
    PASSED = "PASSED"
    PARCIAL = "PARCIAL"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RuleSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# --- TABLA INTERMEDIA ---

profile_rules_association = Table(
    "hardening_profile_rules",
    Base.metadata,
    Column("profile_id", UUID(as_uuid=True), ForeignKey("hardening_profiles.id", ondelete="CASCADE"), primary_key=True),
    Column("rule_id", String(50), ForeignKey("hardening_rule_catalog.id", ondelete="CASCADE"), primary_key=True),
)


# --- TABLAS PRINCIPALES ---

class RuleCatalog(Base):
    __tablename__ = "hardening_rule_catalog"

    id = Column(String(50), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=False)
    standard = Column(String(50), nullable=False)
    standard_version = Column(String(20), default="v1.0.0", nullable=False)
    default_severity = Column(
        Enum(RuleSeverity, values_callable=lambda x: [e.value for e in x]),
        default=RuleSeverity.MEDIUM,
        nullable=False,
    )
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class HardeningProfile(Base):
    __tablename__ = "hardening_profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(150), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    profile_type = Column(
        Enum(ProfileType, values_callable=lambda x: [e.value for e in x]),
        default=ProfileType.CUSTOM,
        nullable=False,
    )
    is_active = Column(Boolean, default=True, nullable=False)

    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    rules = relationship("RuleCatalog", secondary=profile_rules_association, backref="profiles")


class AuditReport(Base):
    __tablename__ = "hardening_audit_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), nullable=False)
    vdom_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Se usa values_callable para asegurar que extraiga la cadena exacta del enum ('CUSTOM_ADHOC')
    execution_type = Column(
        Enum(ExecutionType, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    profile_id = Column(UUID(as_uuid=True), ForeignKey("hardening_profiles.id", ondelete="SET NULL"), nullable=True)
    
    score = Column(Float, nullable=False)
    total_passed = Column(Integer, default=0, nullable=False)
    total_failed = Column(Integer, default=0, nullable=False)
    total_not_applicable = Column(Integer, default=0, nullable=False)

    executed_by = Column(UUID(as_uuid=True), nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    findings = relationship("AuditFinding", back_populates="report", cascade="all, delete-orphan")


class AuditFinding(Base):
    __tablename__ = "hardening_audit_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = Column(UUID(as_uuid=True), ForeignKey("hardening_audit_reports.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(50), ForeignKey("hardening_rule_catalog.id"), nullable=False)

    status = Column(
        Enum(FindingStatus, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    compliance_score = Column(Float, default=0.0, nullable=False)
    severity = Column(
        Enum(RuleSeverity, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    current_value = Column(Text, nullable=True)
    expected_value = Column(Text, nullable=True)
    remediation_cmd = Column(Text, nullable=True)

    report = relationship("AuditReport", back_populates="findings")