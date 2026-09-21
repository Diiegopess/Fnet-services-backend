"""add rule_spec and update hardening models

Revision ID: 039002722806
Revises: 70f6e9d3abb9
Create Date: 2026-09-21 09:15:12.422365

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '039002722806'
down_revision: Union[str, Sequence[str], None] = '70f6e9d3abb9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Eliminar restricciones de clave foránea existentes hacia hardening_rule_catalog
    op.drop_constraint('hardening_audit_findings_rule_id_fkey', 'hardening_audit_findings', type_='foreignkey')
    op.drop_constraint('hardening_profile_rules_rule_id_fkey', 'hardening_profile_rules', type_='foreignkey')

    # 2. Actualizar hardening_rule_catalog con las nuevas columnas
    op.add_column('hardening_rule_catalog', sa.Column('required_endpoint', sa.String(length=255), server_default='', nullable=False))
    op.add_column('hardening_rule_catalog', sa.Column('rule_spec', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False))
    
    # 3. Actualizar la Primary Key de hardening_rule_catalog a compuesta (id, standard_version)
    op.drop_constraint('hardening_rule_catalog_pkey', 'hardening_rule_catalog', type_='primary')
    op.create_primary_key('hardening_rule_catalog_pkey', 'hardening_rule_catalog', ['id', 'standard_version'])

    # 4. Agregar la columna standard_version a hardening_profile_rules
    op.add_column('hardening_profile_rules', sa.Column('standard_version', sa.String(length=20), server_default='v1.0.0', nullable=False))
    
    # -------------------------------------------------------------------------
    # PASO CLAVE: Sincronizar versiones y limpiar asociaciones huérfanas
    # -------------------------------------------------------------------------
    # Copia la versión real de la regla si ya existía con otra versión en hardening_rule_catalog
    op.execute("""
        UPDATE hardening_profile_rules hpr
        SET standard_version = hrc.standard_version
        FROM hardening_rule_catalog hrc
        WHERE hpr.rule_id = hrc.id;
    """)

    # Elimina filas de la tabla intermedia que apunten a reglas inexistentes
    op.execute("""
        DELETE FROM hardening_profile_rules
        WHERE (rule_id, standard_version) NOT IN (
            SELECT id, standard_version FROM hardening_rule_catalog
        );
    """)

    # 5. Actualizar la Primary Key de hardening_profile_rules
    op.drop_constraint('hardening_profile_rules_pkey', 'hardening_profile_rules', type_='primary')
    op.create_primary_key('hardening_profile_rules_pkey', 'hardening_profile_rules', ['profile_id', 'rule_id', 'standard_version'])
    
    # 6. Recrear la foreign key compuesta (ahora pasará sin conflictos de integridad)
    op.create_foreign_key(
        'fk_hardening_profile_rules_catalog',
        'hardening_profile_rules',
        'hardening_rule_catalog',
        ['rule_id', 'standard_version'],
        ['id', 'standard_version'],
        ondelete='CASCADE'
    )

    # 7. Actualizar hardening_audit_findings
    op.add_column('hardening_audit_findings', sa.Column('standard_version', sa.String(length=20), server_default='v1.0.0', nullable=False))


def downgrade() -> None:
    # Revertir cambios en hardening_audit_findings
    op.drop_column('hardening_audit_findings', 'standard_version')

    # Revertir cambios en hardening_profile_rules
    op.drop_constraint('fk_hardening_profile_rules_catalog', 'hardening_profile_rules', type_='foreignkey')
    op.drop_constraint('hardening_profile_rules_pkey', 'hardening_profile_rules', type_='primary')
    op.drop_column('hardening_profile_rules', 'standard_version')
    op.create_primary_key('hardening_profile_rules_pkey', 'hardening_profile_rules', ['profile_id', 'rule_id'])
    
    # Revertir Primary Key de hardening_rule_catalog
    op.drop_constraint('hardening_rule_catalog_pkey', 'hardening_rule_catalog', type_='primary')
    op.create_primary_key('hardening_rule_catalog_pkey', 'hardening_rule_catalog', ['id'])

    # Revertir columnas de hardening_rule_catalog
    op.drop_column('hardening_rule_catalog', 'rule_spec')
    op.drop_column('hardening_rule_catalog', 'required_endpoint')

    # Recrear foreign keys simples originales
    op.create_foreign_key('hardening_profile_rules_rule_id_fkey', 'hardening_profile_rules', 'hardening_rule_catalog', ['rule_id'], ['id'], ondelete='CASCADE')
    op.create_foreign_key('hardening_audit_findings_rule_id_fkey', 'hardening_audit_findings', 'hardening_rule_catalog', ['rule_id'], ['id'])