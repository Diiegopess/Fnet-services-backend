# app/services/hardening/seeder.py

import json
import logging
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.hardening.models import HardeningProfile, ProfileType, RuleCatalog, RuleSeverity
from app.hardening.repository import HardeningRepository
from app.infrastructure.db.seeder_registry import SeederRegistry

logger = logging.getLogger(__name__)


@SeederRegistry.register
async def seed_hardening_data(session: AsyncSession) -> None:
    """Seeder declarativo: Lee manifiestos de benchmarks en JSON,
    sincroniza el catálogo de reglas y actualiza/crea perfiles de sistema.
    """
    repository = HardeningRepository(session)

    benchmarks_dir = Path(__file__).resolve().parent / "benchmarks"
    if not benchmarks_dir.exists():
        logger.warning(f"--> [HARDENING SEEDER] No existe el directorio de benchmarks: {benchmarks_dir}")
        return

    json_files = sorted(list(benchmarks_dir.rglob("*.json")))
    if not json_files:
        logger.warning(f"--> [HARDENING SEEDER] No se encontraron archivos JSON en: {benchmarks_dir}")
        return

    for file_path in json_files:
        logger.info(f"--> [HARDENING SEEDER] Procesando manifiesto: {file_path.name}")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                benchmark = json.load(f)

            standard = benchmark.get("standard")
            version = benchmark.get("standard_version")
            raw_rules = benchmark.get("rules", [])

            if not standard or not version or not isinstance(raw_rules, list):
                logger.warning(f"--> [HARDENING SEEDER] Estructura inválida en {file_path.name}. Omite proceso.")
                continue

            rules_payload = []
            rule_ids = []

            for rule_entry in raw_rules:
                rule_id = rule_entry.get("id")
                if not rule_id:
                    continue

                rule_spec = rule_entry.get("rule_spec", {})
                req_endpoint = rule_entry.get("required_endpoint") or rule_spec.get("required_endpoint", "")

                # Normalización segura a Enum
                raw_severity = rule_entry.get("default_severity", "MEDIUM").upper()
                severity_enum = getattr(RuleSeverity, raw_severity, RuleSeverity.MEDIUM)

                rules_payload.append({
                    "id": str(rule_id),
                    "standard_version": version,
                    "name": rule_entry.get("name", rule_id),
                    "description": rule_entry.get("description"),
                    "category": rule_entry.get("category", "General"),
                    "standard": standard,
                    "default_severity": severity_enum,
                    "required_endpoint": req_endpoint,
                    "rule_spec": rule_spec,
                    "is_active": rule_entry.get("is_active", True),
                })
                rule_ids.append(str(rule_id))

            if not rules_payload:
                continue

            # 1. Sincronizar Reglas en RuleCatalog
            await repository.sync_rule_catalog(rules_payload)

            # 2. Cargar las entidades RuleCatalog persistidas en la sesión actual
            rules_stmt = select(RuleCatalog).where(
                RuleCatalog.id.in_(rule_ids),
                RuleCatalog.standard_version == version
            )
            saved_rules = list((await session.execute(rules_stmt)).scalars().all())

            # 3. Sincronizar / Crear el Perfil de Sistema (SYSTEM)
            profile_name = benchmark.get("title", f"Perfil Base {standard} {version}")
            is_system_profile = benchmark.get("is_system_profile", True)

            if is_system_profile:
                stmt = select(HardeningProfile).options(
                    selectinload(HardeningProfile.rules)
                ).where(
                    HardeningProfile.name == profile_name,
                    HardeningProfile.profile_type == ProfileType.SYSTEM
                )
                profile = (await session.execute(stmt)).scalar_one_or_none()

                if not profile:
                    profile = HardeningProfile(
                        id=uuid4(),
                        name=profile_name,
                        description=benchmark.get("description"),
                        standard_version=version,
                        profile_type=ProfileType.SYSTEM,
                        is_active=True,
                        created_by=None,  # Perfil nativo del sistema
                        rules=saved_rules,
                    )
                    session.add(profile)
                    logger.info(f"--> [HARDENING SEEDER] Perfil de sistema creado: '{profile_name}'")
                else:
                    profile.description = benchmark.get("description", profile.description)
                    profile.standard_version = version
                    profile.rules = saved_rules
                    logger.info(f"--> [HARDENING SEEDER] Perfil de sistema actualizado: '{profile_name}'")

            # 4. Flush para emitir el SQL a Postgres sin cerrar la transacción atómica
            await session.flush()

        except Exception as e:
            logger.error(f"--> [HARDENING SEEDER] Error al procesar {file_path.name}: {e}")
            raise e  # Propagar el error para que el runner haga rollback si falla un JSON