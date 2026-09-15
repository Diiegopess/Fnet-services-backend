# app/services/hardening/seeder.py
import logging
import uuid
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.infrastructure.db.seeder_registry import SeederRegistry
from app.services.hardening.models import HardeningProfile, ProfileType, RuleCatalog
from app.services.hardening.strategies.registry import RuleRegistry

# Módulos de reglas que se auto-registran mediante @register_rule
import app.services.hardening.strategies.fortinet.system_rules  # noqa: F401
import app.services.hardening.strategies.gamma.admin_rules  # noqa: F401
import app.services.hardening.strategies.cis.network_rules  # noqa: F401 

logger = logging.getLogger(__name__)


@SeederRegistry.register
async def seed_hardening_domain(session) -> None:
    """Sincroniza las reglas de Hardening y perfiles SYSTEM en la BD."""
    code_rules = RuleRegistry.get_all_rules()
    if not code_rules:
        logger.warning("[SEED_HARDENING] No hay reglas registradas en RuleRegistry.")
        return

    res_db_rules = await session.execute(select(RuleCatalog))
    db_rules = {r.id: r for r in res_db_rules.scalars().all()}
    rules_by_standard: dict[str, list[RuleCatalog]] = {}

    for rule_inst in code_rules:
        rule_id = rule_inst.rule_id
        if rule_id not in db_rules:
            db_rule = RuleCatalog(
                id=rule_id,
                name=rule_inst.name,
                description=rule_inst.description,
                category=rule_inst.category,
                standard=rule_inst.standard,
                default_severity=rule_inst.default_severity,
                is_active=True,
            )
            session.add(db_rule)
            db_rules[rule_id] = db_rule
            logger.info(f"[SEED_HARDENING] Regla agregada: {rule_id}")
        else:
            db_rule = db_rules[rule_id]
            # Sincronizar datos si cambiaron en el código
            db_rule.name = rule_inst.name
            db_rule.description = rule_inst.description
            db_rule.category = rule_inst.category
            db_rule.standard = rule_inst.standard
            db_rule.default_severity = rule_inst.default_severity

        standard_key = rule_inst.standard.upper()
        rules_by_standard.setdefault(standard_key, []).append(db_rule)

    await session.flush()

    res_profiles = await session.execute(
        select(HardeningProfile).options(selectinload(HardeningProfile.rules))
    )
    db_profiles = {p.name: p for p in res_profiles.scalars().all()}

    for standard_name, rules_list in rules_by_standard.items():
        profile_name = f"Perfil Base {standard_name}"
        profile_desc = f"Plantilla predeterminada del estándar {standard_name}."

        if profile_name not in db_profiles:
            profile = HardeningProfile(
                id=uuid.uuid4(),
                name=profile_name,
                description=profile_desc,
                profile_type=ProfileType.SYSTEM,
                is_active=True,
                rules=rules_list,
            )
            session.add(profile)
            logger.info(f"[SEED_HARDENING] Perfil creado: {profile_name}")
        else:
            profile = db_profiles[profile_name]
            profile.rules = rules_list

    await session.flush()