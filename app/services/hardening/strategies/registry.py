from typing import Dict, List, Type

from app.services.hardening.exceptions import RuleNotFoundException
from app.services.hardening.strategies.base import BaseRule


class RuleRegistry:
    """Registro global (Singleton/Registry Pattern) de reglas en código Python."""

    _rules: Dict[str, Type[BaseRule]] = {}

    @classmethod
    def register(cls, rule_cls: Type[BaseRule]) -> Type[BaseRule]:
        """Decorador para registrar reglas automáticamente.

        Ejemplo de uso:
            @RuleRegistry.register
            class SSHTimeoutRule(BaseRule):
                rule_id = "FORTI-001"
                ...
        """
        if not hasattr(rule_cls, "rule_id") or not rule_cls.rule_id:
            raise ValueError(f"La clase {rule_cls.__name__} debe definir un 'rule_id' válido.")

        cls._rules[rule_cls.rule_id] = rule_cls
        return rule_cls

    @classmethod
    def get_rule(cls, rule_id: str) -> BaseRule:
        """Instancia y retorna la regla correspondiente a la ID provista."""
        rule_cls = cls._rules.get(rule_id)
        if not rule_cls:
            raise RuleNotFoundException(rule_id)
        return rule_cls()

    @classmethod
    def get_all_rules(cls) -> List[BaseRule]:
        """Retorna instancias de todas las reglas registradas."""
        return [rule_cls() for rule_cls in cls._rules.values()]

    @classmethod
    def is_registered(cls, rule_id: str) -> bool:
        """Verifica si una ID de regla está implementada en código."""
        return rule_id in cls._rules


# Decorador directo para facilidad de sintaxis
register_rule = RuleRegistry.register