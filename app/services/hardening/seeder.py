# app/services/hardening/seeder.py

import json
import logging
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.db.seeder_registry import SeederRegistry
from app.services.hardening.models import HardeningProfile, ProfileType, RuleCatalog
from app.services.hardening.repository import HardeningRepository

logger = logging.getLogger(__name__)


@SeederRegistry.register
async def seed_hardening_data(session: AsyncSession) -> None:
    """Seeder desacoplado: lee benchmarks en JSON de forma recursiva,

    sincroniza RuleCatalog y actualiza perfiles SYSTEM alineados por versión.
    """
    repository = HardeningRepository(session)

    # 1. Localizar la carpeta de benchmarks JSON
    benchmarks_dir = Path(__file__).resolve().parent / "benchmarks"
    if not benchmarks_dir.exists():
        logger.warning(f"--> [HARDENING SEEDER] No existe el directorio de benchmarks: {benchmarks_dir}")
        return

    # rglob permite leer recursivamente archivos en subdirectorios (ej: benchmarks/cis_v1.0.1/*.json)
    json_files = sorted(list(benchmarks_dir.rglob("*.json")))
    if not json_files:
        logger.warning(f"--> [HARDENING SEEDER] No se encontraron archivos .json en: {benchmarks_dir}")
        return

    # 2. Leer y construir el payload de reglas desde todos los archivos JSON
    rules_payload = []
    for file_path in json_files:
        logger.info(f"--> [HARDENING SEEDER] Leyendo especificaciones desde: {file_path.relative_to(benchmarks_dir)}")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, list):
                for rule_entry in data:
                    rule_id = rule_entry.get("id")
                    if not rule_id:
                        logger.warning(f"--> [HARDENING SEEDER] Entrada ignorada por falta de 'id' en {file_path.name}")
                        continue

                    # Extraer rule_spec completo
                    rule_spec = rule_entry.get("rule_spec", {})
                    required_endpoint = (
                        rule_spec.get("required_endpoint") 
                        or rule_entry.get("required_endpoint", "")
                    )

                    rules_payload.append({
                        "id": str(rule_id),
                        "name": rule_entry.get("name", rule_id),
                        "description": rule_entry.get("description"),
                        "category": rule_entry.get("category", "General"),
                        "standard": rule_entry.get("standard", "CIS"),
                        "standard_version": rule_entry.get("standard_version", "v1.0.1"),
                        "default_severity": rule_entry.get("default_severity", "MEDIUM"),
                        "required_endpoint": required_endpoint,
                        "rule_spec": rule_spec,
                        "is_active": rule_entry.get("is_active", True),
                    })
        except Exception as e:
            logger.error(f"--> [HARDENING SEEDER] Error al parsear {file_path.name}: {e}")

    if not rules_payload:
        logger.warning("--> [HARDENING SEEDER] No se construyó ningún payload válido de reglas desde los JSON.")
        return

    # 3. Sincronizar las reglas híbridas (metadatos + JSONB) en la BD
    logger.info(f"--> [HARDENING SEEDER] Sincronizando {len(rules_payload)} reglas con la BD...")
    await repository.sync_rule_catalog(rules_payload)

    # 4. Obtener todas las reglas activas actualizadas desde la BD
    rules_stmt = select(RuleCatalog).where(RuleCatalog.is_active.is_(True))
    all_rules_result = await session.execute(rules_stmt)
    catalog_rules = list(all_rules_result.scalars().all())

    # 5. Sincronizar / Asignar reglas a los Perfiles de Sistema (SYSTEM)
    stmt = select(HardeningProfile).options(selectinload(HardeningProfile.rules)).where(
        HardeningProfile.profile_type == ProfileType.SYSTEM
    )
    result = await session.execute(stmt)
    system_profiles = result.scalars().all()

    target_standard_version = "v1.0.1"

    if not system_profiles:
        logger.info(f"--> [HARDENING SEEDER] Creando perfil base inicial CIS Benchmark ({target_standard_version})...")
        cis_rules = [
            r for r in catalog_rules 
            if r.standard == "CIS" and getattr(r, "standard_version", None) == target_standard_version
        ]

        default_profile = HardeningProfile(
            id=uuid4(),
            name="Perfil Base CIS",
            description=f"Plantilla predeterminada del estándar CIS Benchmark {target_standard_version}.",
            standard_version=target_standard_version,
            profile_type=ProfileType.SYSTEM,
            is_active=True,
            rules=cis_rules,
        )

        session.add(default_profile)
        await session.commit()
        logger.info("--> [HARDENING SEEDER] Perfil base creado con éxito.")
    else:
        logger.info("--> [HARDENING SEEDER] Actualizando reglas asociadas a los perfiles de sistema...")
        for profile in system_profiles:
            profile_name_upper = profile.name.upper()
            prof_version = getattr(profile, "standard_version", target_standard_version)

            if "CIS" in profile_name_upper:
                profile.standard_version = prof_version
                profile.rules = [
                    r for r in catalog_rules 
                    if r.standard == "CIS" and getattr(r, "standard_version", None) == prof_version
                ]
            elif "GAMMA" in profile_name_upper:
                profile.rules = [r for r in catalog_rules if r.standard == "GAMMA"]
            elif "FORTINET" in profile_name_upper:
                profile.rules = [r for r in catalog_rules if r.standard in ("FORTINET", "FORTI")]

        await session.commit()
        logger.info("--> [HARDENING SEEDER] Perfiles actualizados exitosamente con sus reglas correspondientes.")


# --- BLOQUE DE EJECUCIÓN MANUAL DIRECTA ---
if __name__ == "__main__":
    import asyncio
    from app.infrastructure.db.database import AsyncSessionLocal

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    async def main():
        print("\n>>> INICIANDO SEEDER DECLARATIVO MANUALMENTE...")
        async with AsyncSessionLocal() as session:
            await seed_hardening_data(session)
        print(">>> FINALIZADO CON ÉXITO.\n")

    asyncio.run(main())