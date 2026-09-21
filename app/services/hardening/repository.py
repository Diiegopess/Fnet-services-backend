# app/services/hardening/repository.py

from typing import List, Optional, Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.services.hardening.exceptions import ProfileNotFoundException
from app.services.hardening.models import (
    AuditFinding,
    AuditReport,
    ExecutionType,
    HardeningProfile,
    RuleCatalog,
)


class HardeningRepository:
    """Capa de persistencia desacoplada para el módulo de Hardening."""

    def __init__(self, session: AsyncSession):
        self.session = session

    # --- Sincronización de Catálogo Híbrido (JSONB) ---
    async def sync_rule_catalog(self, rules_data: List[dict]) -> None:
        """Sincroniza el catálogo maestro en BD a partir de especificaciones JSON."""
        for data in rules_data:
            version = data.get("standard_version", "v1.0.0")
            
            # Búsqueda por clave compuesta: ID + Versión
            stmt = select(RuleCatalog).where(
                RuleCatalog.id == data["id"],
                RuleCatalog.standard_version == version,
            )
            result = await self.session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                existing.name = data["name"]
                existing.description = data.get("description")
                existing.category = data["category"]
                existing.standard = data["standard"]
                existing.default_severity = data["default_severity"]
                existing.required_endpoint = data["required_endpoint"]
                existing.rule_spec = data["rule_spec"]
                existing.is_active = data.get("is_active", True)
            else:
                new_rule = RuleCatalog(
                    id=data["id"],
                    standard_version=version,
                    name=data["name"],
                    description=data.get("description"),
                    category=data["category"],
                    standard=data["standard"],
                    default_severity=data["default_severity"],
                    required_endpoint=data["required_endpoint"],
                    rule_spec=data["rule_spec"],
                    is_active=data.get("is_active", True),
                )
                self.session.add(new_rule)

        await self.session.commit()

    # --- Consultas de Reglas para el Motor Declarativo ---
    async def get_rules_by_ids(
        self, rule_ids: List[str], standard_version: Optional[str] = None
    ) -> Sequence[RuleCatalog]:
        """Obtiene las especificaciones de reglas activas filtradas por ID y versión."""
        stmt = select(RuleCatalog).where(
            RuleCatalog.id.in_(rule_ids),
            RuleCatalog.is_active.is_(True),
        )
        if standard_version:
            stmt = stmt.where(RuleCatalog.standard_version == standard_version)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_all_active_rules(
        self, standard: Optional[str] = None, standard_version: Optional[str] = None
    ) -> Sequence[RuleCatalog]:
        """Obtiene todo el catálogo maestro para auditorías de estándar completo."""
        stmt = select(RuleCatalog).where(RuleCatalog.is_active.is_(True))
        if standard:
            stmt = stmt.where(RuleCatalog.standard == standard)
        if standard_version:
            stmt = stmt.where(RuleCatalog.standard_version == standard_version)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    # --- Consultas de Perfiles ---
    async def get_all_profiles(
        self, standard_version: Optional[str] = None
    ) -> Sequence[HardeningProfile]:
        """Obtiene todos los perfiles de hardening activos cargando sus reglas asociadas."""
        stmt = (
            select(HardeningProfile)
            .options(selectinload(HardeningProfile.rules))
            .where(HardeningProfile.is_active.is_(True))
        )

        if standard_version:
            stmt = stmt.where(HardeningProfile.standard_version == standard_version)

        stmt = stmt.order_by(HardeningProfile.created_at.desc())

        result = await self.session.execute(stmt)
        return result.unique().scalars().all()

    async def get_profile_by_id(self, profile_id: UUID) -> HardeningProfile:
        """Obtiene un perfil cargando impacientemente sus reglas asociadas."""
        stmt = (
            select(HardeningProfile)
            .options(selectinload(HardeningProfile.rules))
            .where(HardeningProfile.id == profile_id)
        )
        result = await self.session.execute(stmt)
        profile = result.scalar_one_or_none()
        if not profile:
            raise ProfileNotFoundException(str(profile_id))
        return profile

    async def get_profile_rule_ids(self, profile_id: UUID) -> List[str]:
        """Retorna únicamente la lista de IDs de reglas asociadas a un perfil."""
        profile = await self.get_profile_by_id(profile_id)
        return [rule.id for rule in profile.rules if rule.is_active]

    # --- Persistencia y Consulta de Resultados ---
    async def save_audit_report(
        self,
        device_id: UUID,
        execution_type: ExecutionType,
        score: float,
        total_passed: int,
        total_failed: int,
        total_not_applicable: int,
        findings_data: List[dict],
        vdom_id: Optional[UUID] = None,
        profile_id: Optional[UUID] = None,
        executed_by: Optional[UUID] = None,
    ) -> AuditReport:
        """Crea la cabecera del reporte y guarda todos sus hallazgos asociados."""
        report = AuditReport(
            device_id=device_id,
            vdom_id=vdom_id,
            execution_type=execution_type,
            profile_id=profile_id,
            score=score,
            total_passed=total_passed,
            total_failed=total_failed,
            total_not_applicable=total_not_applicable,
            executed_by=executed_by,
        )
        self.session.add(report)
        await self.session.flush()

        for f_data in findings_data:
            finding = AuditFinding(
                report_id=report.id,
                rule_id=f_data["rule_id"],
                standard_version=f_data.get("standard_version", "v1.0.0"),
                status=f_data["status"],
                compliance_score=f_data.get("compliance_score", 0.0),
                severity=f_data["severity"],
                current_value=f_data.get("current_value"),
                expected_value=f_data.get("expected_value"),
                remediation_cmd=f_data.get("remediation_cmd"),
            )
            self.session.add(finding)

        await self.session.commit()

        stmt = (
            select(AuditReport)
            .options(selectinload(AuditReport.findings))
            .where(AuditReport.id == report.id)
        )
        res = await self.session.execute(stmt)
        return res.scalar_one()

    async def get_report_by_id(self, report_id: UUID) -> Optional[AuditReport]:
        """Obtiene un reporte de auditoría completo con sus hallazgos."""
        stmt = (
            select(AuditReport)
            .options(selectinload(AuditReport.findings))
            .where(AuditReport.id == report_id)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_reports(
        self,
        device_id: Optional[UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[AuditReport]:
        """Obtiene la lista de reportes de auditoría paginados."""
        stmt = (
            select(AuditReport)
            .options(selectinload(AuditReport.findings))
        )

        if device_id:
            stmt = stmt.where(AuditReport.device_id == device_id)

        stmt = stmt.order_by(AuditReport.executed_at.desc()).limit(limit).offset(offset)

        result = await self.session.execute(stmt)
        return result.unique().scalars().all()