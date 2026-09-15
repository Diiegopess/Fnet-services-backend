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
    """Capa de persistencia para el módulo de Hardening."""

    def __init__(self, session: AsyncSession):
        self.session = session

    # --- Sincronización de Catálogo ---
    async def sync_rule_catalog(self, rules_data: List[dict]) -> None:
        """Sincroniza el catálogo maestro en BD con las reglas registradas en Python."""
        for data in rules_data:
            stmt = select(RuleCatalog).where(RuleCatalog.id == data["id"])
            result = await self.session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                existing.name = data["name"]
                existing.description = data["description"]
                existing.category = data["category"]
                existing.standard = data["standard"]
                existing.default_severity = data["default_severity"]
            else:
                new_rule = RuleCatalog(
                    id=data["id"],
                    name=data["name"],
                    description=data["description"],
                    category=data["category"],
                    standard=data["standard"],
                    default_severity=data["default_severity"],
                )
                self.session.add(new_rule)

        await self.session.commit()

    # --- Consultas de Perfiles ---
    async def get_all_profiles(self) -> Sequence[HardeningProfile]:
        """Obtiene todos los perfiles de hardening activos cargando sus reglas asociadas."""
        stmt = (
            select(HardeningProfile)
            .options(selectinload(HardeningProfile.rules))
            .where(HardeningProfile.is_active.is_(True))
            .order_by(HardeningProfile.created_at.desc())
        )
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

    # --- Persistencia de Resultados ---
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
                status=f_data["status"],
                severity=f_data["severity"],
                current_value=f_data["current_value"],
                expected_value=f_data["expected_value"],
                remediation_cmd=f_data["remediation_cmd"],
            )
            self.session.add(finding)

        await self.session.commit()
        await self.session.refresh(report)
        return report