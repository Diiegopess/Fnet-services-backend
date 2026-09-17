# app/services/hardening/seeder.py

import logging
from uuid import uuid4
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

# Forzar la importación del paquete de estrategias para ejecutar los decoradores de registro
import app.services.hardening.strategies  # noqa: F401
from app.infrastructure.db.seeder_registry import SeederRegistry
from app.services.hardening.models import HardeningProfile, ProfileType, RuleCatalog
from app.services.hardening.repository import HardeningRepository
from app.services.hardening.strategies.registry import RuleRegistry

logger = logging.getLogger(__name__)


@SeederRegistry.register
async def seed_hardening_data(session: AsyncSession) -> None:
    """Seeder para sincronizar el catálogo de reglas y actualizar los perfiles base."""
    repository = HardeningRepository(session)

    # 1. Obtener la lista de reglas registradas
    registered_rules = RuleRegistry.get_all_rules()
    if not registered_rules:
        logger.warning("--> [HARDENING SEEDER] No se encontraron reglas registradas en memoria.")
        return

    # 2. Mapear las instancias de regla extrayendo el valor del Enum de severidad si aplica
    rules_payload = []
    for rule in registered_rules:
        rule_identifier = getattr(rule, "rule_id", getattr(rule, "id", None))
        
        if not rule_identifier:
            logger.warning(f"--> [HARDENING SEEDER] Regla omitida por no tener 'rule_id' ni 'id': {type(rule).__name__}")
            continue

        raw_severity = getattr(rule, "severity", getattr(rule, "default_severity", "MEDIUM"))
        # Extraer string si es Enum
        severity_value = raw_severity.value if hasattr(raw_severity, "value") else str(raw_severity)

        rules_payload.append({
            "id": str(rule_identifier),
            "name": getattr(rule, "name", type(rule).__name__),
            "description": getattr(rule, "description", None),
            "category": getattr(rule, "category", "General"),
            "standard": getattr(rule, "standard", "CIS"),
            "standard_version": getattr(rule, "standard_version", "v1.2.0"),
            "default_severity": severity_value,
        })

    if not rules_payload:
        logger.warning("--> [HARDENING SEEDER] No se construyó ningún payload válido de reglas.")
        return

    # 3. Sincronizar las reglas con la base de datos
    logger.info(f"--> [HARDENING SEEDER] Sincronizando {len(rules_payload)} reglas con la BD...")
    await repository.sync_rule_catalog(rules_payload)

    # 4. Obtener todas las reglas activas actualizadas desde la BD
    rules_stmt = select(RuleCatalog).where(RuleCatalog.is_active.is_(True))
    all_rules_result = await session.execute(rules_stmt)
    catalog_rules = list(all_rules_result.scalars().all())

    # 5. Sincronizar / Asignar reglas a los Perfiles Sistema (SYSTEM)
    stmt = select(HardeningProfile).options(selectinload(HardeningProfile.rules)).where(
        HardeningProfile.profile_type == ProfileType.SYSTEM
    )
    result = await session.execute(stmt)
    system_profiles = result.scalars().all()

    if not system_profiles:
        logger.info("--> [HARDENING SEEDER] Creando perfil base inicial CIS Benchmark...")
        
        cis_rules = [r for r in catalog_rules if r.standard == "CIS"]

        default_profile = HardeningProfile(
            id=uuid4(),
            name="Perfil Base CIS",
            description="Plantilla predeterminada del estándar CIS.",
            profile_type=ProfileType.SYSTEM,
            is_active=True,
            rules=cis_rules
        )

        session.add(default_profile)
        await session.commit()
        logger.info("--> [HARDENING SEEDER] Perfil base creado con éxito.")
    else:
        logger.info("--> [HARDENING SEEDER] Actualizando reglas asociadas a los perfiles de sistema...")
        for profile in system_profiles:
            if "CIS" in profile.name.upper():
                profile.rules = [r for r in catalog_rules if r.standard == "CIS"]
            elif "GAMMA" in profile.name.upper():
                profile.rules = [r for r in catalog_rules if r.standard == "GAMMA"]
            elif "FORTINET" in profile.name.upper():
                profile.rules = [r for r in catalog_rules if r.standard in ("FORTINET", "FORTI")]

        await session.commit()
        logger.info("--> [HARDENING SEEDER] Perfiles actualizados exitosamente con todas las reglas.")