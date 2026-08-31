"""add_devices_and_vdoms

Revision ID: 0001_add_devices_and_vdoms
Revises: 
Create Date: 2026-08-31 00:00:00.000000

"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Identificadores de revisión de Alembic
revision: str = "0001_add_devices_and_vdoms"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Tabla: DEVICES (Chasis Físico)
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

    # 2. Tabla: DEVICE_VDOMS (Particiones Lógicas Multi-tenant)
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


def downgrade() -> None:
    op.drop_table("device_vdoms")
    op.drop_table("devices")