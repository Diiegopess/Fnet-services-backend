"""Initial schema consolidation

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-09-25 00:00:00.000000

"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Identificadores de revisión de Alembic
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # =========================================================================
    # 1. TABLAS INDEPENDIENTES (Sin Claves Foráneas)
    # =========================================================================

    # 1.1 Activity Logs (Formerly Audit Logs)
    op.create_table(
        "activity_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", sa.String(length=255), nullable=True, comment="Identificador único del evento en el bus para trazabilidad e idempotencia"),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(op.f("ix_activity_logs_event_id"), "activity_logs", ["event_id"], unique=False)
    op.create_index(op.f("ix_activity_logs_event_type"), "activity_logs", ["event_type"], unique=False)
    op.create_index(op.f("ix_activity_logs_user_id"), "activity_logs", ["user_id"], unique=False)
    op.create_index(op.f("ix_activity_logs_created_at"), "activity_logs", ["created_at"], unique=False)

    # 1.2 Auth Credentials
    op.create_table(
        "auth_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("google_id", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(op.f("ix_auth_credentials_email"), "auth_credentials", ["email"], unique=True)
    op.create_index(op.f("ix_auth_credentials_google_id"), "auth_credentials", ["google_id"], unique=True)

    # 1.3 Clients
    op.create_table(
        "clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("tax_id", sa.String(length=50), nullable=True),
        sa.Column("contact_email", sa.String(length=255), nullable=True),
        sa.Column("contact_phone", sa.String(length=50), nullable=True),
        sa.Column("address", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(op.f("ix_clients_name"), "clients", ["name"], unique=True)
    op.create_index(op.f("ix_clients_tax_id"), "clients", ["tax_id"], unique=True)

    # 1.4 Permissions
    op.create_table(
        "permissions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
    )
    op.create_index(op.f("ix_permissions_code"), "permissions", ["code"], unique=True)

    # 1.5 Roles
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
    )
    op.create_index(op.f("ix_roles_name"), "roles", ["name"], unique=True)

    # 1.6 Users
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    # 1.7 Devices (Fortigate)
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), server_default="443", nullable=False),
        sa.Column("encrypted_api_token", sa.Text(), nullable=True),
        sa.Column("fortios_version", sa.String(length=20), server_default="7.2", nullable=False),
        sa.Column("serial_number", sa.String(length=100), nullable=True),
        sa.Column("has_vdom_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(op.f("ix_devices_name"), "devices", ["name"], unique=False)
    op.create_index(op.f("ix_devices_host"), "devices", ["host"], unique=True)
    op.create_index(op.f("ix_devices_serial_number"), "devices", ["serial_number"], unique=True)

    # 1.8 Hardening Rule Catalog (Clave Primaria Compuesta)
    op.create_table(
        "hardening_rule_catalog",
        sa.Column("id", sa.String(length=50), nullable=False),
        sa.Column("standard_version", sa.String(length=20), nullable=False, server_default="v1.0.0"),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("standard", sa.String(length=50), nullable=False),
        sa.Column("default_severity", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="ruleseverity"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("required_endpoint", sa.String(length=255), nullable=False),
        sa.Column("rule_spec", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", "standard_version"),
    )

    # 1.9 Hardening Profiles
    op.create_table(
        "hardening_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=150), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("standard_version", sa.String(length=20), nullable=False, server_default="v1.0.1"),
        sa.Column("profile_type", sa.Enum("SYSTEM", "CUSTOM", name="profiletype"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # =========================================================================
    # 2. TABLAS INTERMEDIAS Y DEPENDIENTES (Con Claves Foráneas)
    # =========================================================================

    # 2.1 User Roles (N:M Users <-> Roles)
    op.create_table(
        "user_roles",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    )

    # 2.2 Role Permissions (N:M Roles <-> Permissions)
    op.create_table(
        "role_permissions",
        sa.Column("role_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
    )

    # 2.3 Client Technicians (N:M Clients <-> Users)
    op.create_table(
        "client_technicians",
        sa.Column("client_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("clients.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    )

    # 2.4 Device VDOMs (1:N Devices -> VDOMs, 1:N Clients -> VDOMs)
    op.create_table(
        "device_vdoms",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("clients.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("is_root", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("device_id", "name", name="uq_device_vdom_name"),
    )
    op.create_index(op.f("ix_device_vdoms_device_id"), "device_vdoms", ["device_id"], unique=False)
    op.create_index(op.f("ix_device_vdoms_client_id"), "device_vdoms", ["client_id"], unique=False)

    # 2.5 Hardening Profile Rules (N:M Profiles <-> RuleCatalog con FK Compuesta)
    op.create_table(
        "hardening_profile_rules",
        sa.Column("profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hardening_profiles.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("rule_id", sa.String(length=50), primary_key=True),
        sa.Column("standard_version", sa.String(length=20), primary_key=True),
        sa.ForeignKeyConstraint(
            ["rule_id", "standard_version"],
            ["hardening_rule_catalog.id", "hardening_rule_catalog.standard_version"],
            ondelete="CASCADE",
        ),
    )

    # 2.6 Hardening Audit Reports
    op.create_table(
        "hardening_audit_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vdom_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("execution_type", sa.Enum("FULL_STANDARD", "ASSIGNED_PROFILE", "CUSTOM_ADHOC", name="executiontype"), nullable=False),
        sa.Column("profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hardening_profiles.id", ondelete="SET NULL"), nullable=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("total_passed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("total_failed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("total_not_applicable", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("executed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 2.7 Hardening Audit Findings (FK Compuesta hacia RuleCatalog)
    op.create_table(
        "hardening_audit_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hardening_audit_reports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.String(length=50), nullable=False),
        sa.Column("standard_version", sa.String(length=20), nullable=False, server_default="v1.0.0"),
        sa.Column("status", sa.Enum("PASSED", "PARCIAL", "FAILED", "NOT_APPLICABLE", name="findingstatus"), nullable=False),
        sa.Column("compliance_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.Column("severity", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="ruleseverity"), nullable=False),
        sa.Column("current_value", sa.Text(), nullable=True),
        sa.Column("expected_value", sa.Text(), nullable=True),
        sa.Column("remediation_cmd", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["rule_id", "standard_version"],
            ["hardening_rule_catalog.id", "hardening_rule_catalog.standard_version"],
            ondelete="CASCADE",
        ),
    )


def downgrade() -> None:
    # Eliminación en orden inverso a la creación
    op.drop_table("hardening_audit_findings")
    op.drop_table("hardening_audit_reports")
    op.drop_table("hardening_profile_rules")
    op.drop_table("device_vdoms")
    op.drop_table("client_technicians")
    op.drop_table("role_permissions")
    op.drop_table("user_roles")
    op.drop_table("hardening_profiles")
    op.drop_table("hardening_rule_catalog")
    op.drop_table("devices")
    op.drop_table("users")
    op.drop_table("roles")
    op.drop_table("permissions")
    op.drop_table("clients")
    op.drop_table("auth_credentials")
    op.drop_table("activity_logs")

    # Eliminación de Enum Types creados por PostgreSQL
    sa.Enum(name="findingstatus").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="executiontype").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="profiletype").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="ruleseverity").drop(op.get_bind(), checkfirst=False)