from typing import Dict, List, Set, Tuple, Type

from app.services.hardening.exceptions import RuleNotFoundException
from app.services.hardening.strategies.base import BaseRule


class RuleRegistry:
    """Registro global (Singleton/Registry Pattern) de reglas en código Python."""

    _rules: Dict[str, Type[BaseRule]] = {}

    @classmethod
    def register(cls, rule_cls: Type[BaseRule]) -> Type[BaseRule]:
        if not hasattr(rule_cls, "rule_id") or not rule_cls.rule_id:
            raise ValueError(f"La clase {rule_cls.__name__} debe definir un 'rule_id' válido.")

        cls._rules[rule_cls.rule_id] = rule_cls
        return rule_cls

    @classmethod
    def get_rule(cls, rule_id: str) -> BaseRule:
        rule_cls = cls._rules.get(rule_id)
        if not rule_cls:
            raise RuleNotFoundException(rule_id)
        return rule_cls()

    @classmethod
    def get_rule_class(cls, rule_id: str) -> Type[BaseRule]:
        """Retorna la CLASE sin instanciar para inspeccionar atributos rápida y livianamente."""
        rule_cls = cls._rules.get(rule_id)
        if not rule_cls:
            raise RuleNotFoundException(rule_id)
        return rule_cls

    @classmethod
    def get_all_rules(cls) -> List[BaseRule]:
        return [rule_cls() for rule_cls in cls._rules.values()]

    @classmethod
    def is_registered(cls, rule_id: str) -> bool:
        return rule_id in cls._rules

    # -------------------------------------------------------------------------
    # Método Quirúrgico: Deduplicación de Endpoints directamente desde el Registry
    # -------------------------------------------------------------------------
    @classmethod
    def resolve_required_endpoints(cls, rule_ids: List[str]) -> List[Dict[str, str]]:
        """Extrae y deduplica los endpoints de una lista de IDs de reglas

        sin necesidad de instanciar todas las clases.
        """
        unique_keys: Set[Tuple[str, str]] = set()
        deduplicated: List[Dict[str, str]] = []

        for r_id in rule_ids:
            if not cls.is_registered(r_id):
                continue

            rule_cls = cls.get_rule_class(r_id)
            requirements = getattr(rule_cls, "required_endpoints", [])

            for req in requirements:
                block_name = req.get("block_name")
                endpoint = req.get("endpoint")

                if block_name and endpoint:
                    key = (block_name, endpoint)
                    if key not in unique_keys:
                        unique_keys.add(key)
                        deduplicated.append({"block_name": block_name, "endpoint": endpoint})

        return deduplicated


register_rule = RuleRegistry.register