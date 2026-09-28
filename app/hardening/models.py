import enum
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.db.database import Base


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


# Tabla intermedia N:M
profile_rules_association = Table(
    "hardening_profile_rules",
    Base.metadata,
    Column(
        "profile_id",
        UUID(as_uuid=True),
        ForeignKey("hardening_profiles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("rule_id", String(50), primary_key=True),
    Column("standard_version", String(20), primary_key=True),
    ForeignKeyConstraint(
        ["rule_id", "standard_version"],
        ["hardening_rule_catalog.id", "hardening_rule_catalog.standard_version"],
        ondelete="CASCADE",
    ),
)


class RuleCatalog(Base):
    __tablename__ = "hardening_rule_catalog"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    standard_version: Mapped[str] = mapped_column(String(20), primary_key=True, default="v1.0.0")

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    standard: Mapped[str] = mapped_column(String(50), nullable=False)
    default_severity: Mapped[RuleSeverity] = mapped_column(
        Enum(RuleSeverity, values_callable=lambda x: [e.value for e in x]),
        default=RuleSeverity.MEDIUM,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    required_endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_spec: Mapped[dict] = mapped_column(JSONB, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    profiles: Mapped[List["HardeningProfile"]] = relationship(
        "HardeningProfile",
        secondary=profile_rules_association,
        back_populates="rules",
    )


class HardeningProfile(Base):
    __tablename__ = "hardening_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    standard_version: Mapped[str] = mapped_column(String(20), default="v1.0.1", nullable=False)
    profile_type: Mapped[ProfileType] = mapped_column(
        Enum(ProfileType, values_callable=lambda x: [e.value for e in x]),
        default=ProfileType.CUSTOM,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    rules: Mapped[List[RuleCatalog]] = relationship(
        "RuleCatalog",
        secondary=profile_rules_association,
        back_populates="profiles",
    )


class AuditReport(Base):
    __tablename__ = "hardening_audit_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    vdom_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    execution_type: Mapped[ExecutionType] = mapped_column(
        Enum(ExecutionType, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hardening_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    score: Mapped[float] = mapped_column(Float, nullable=False)
    total_passed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_not_applicable: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    executed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    findings: Mapped[List["AuditFinding"]] = relationship(
        "AuditFinding", back_populates="report", cascade="all, delete-orphan"
    )


class AuditFinding(Base):
    __tablename__ = "hardening_audit_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hardening_audit_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(String(50), nullable=False)
    standard_version: Mapped[str] = mapped_column(String(20), default="v1.0.0", nullable=False)

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    severity: Mapped[RuleSeverity] = mapped_column(
        Enum(RuleSeverity, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    current_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_cmd: Mapped[str | None] = mapped_column(Text, nullable=True)

    report: Mapped[AuditReport] = relationship("AuditReport", back_populates="findings")

    # Clave Foránea Compuesta hacia RuleCatalog para mantener la consistencia
    __table_args__ = (
        ForeignKeyConstraint(
            ["rule_id", "standard_version"],
            ["hardening_rule_catalog.id", "hardening_rule_catalog.standard_version"],
            ondelete="CASCADE",
        ),
    )