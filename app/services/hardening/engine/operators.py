# app/services/hardening/engine/operators.py

from typing import Any, List, Set, Union


class OperatorRegistry:
    """Catálogo cerrado de operadores de comparación para evaluación declarativa."""

    @staticmethod
    def equals(actual: Any, expected: Any) -> bool:
        if actual is None:
            return expected is None
        return str(actual).strip().lower() == str(expected).strip().lower()

    @staticmethod
    def not_equals(actual: Any, expected: Any) -> bool:
        return not OperatorRegistry.equals(actual, expected)

    @staticmethod
    def in_list(actual: Any, expected_list: List[Any]) -> bool:
        if actual is None:
            return False
        normalized_list = [str(x).strip().lower() for x in expected_list]
        return str(actual).strip().lower() in normalized_list

    @staticmethod
    def not_in(actual: Any, forbidden_list: List[Any]) -> bool:
        if actual is None:
            return True
        normalized_list = [
            str(x).strip().lower() if x is not None else None for x in forbidden_list
        ]
        return str(actual).strip().lower() not in normalized_list

    @staticmethod
    def disjoint_tokens(actual: Union[str, List[str]], forbidden_tokens: List[str]) -> bool:
        """Verifica que ningún token prohibido esté presente en la cadena o lista actual.
        
        Útil para campos tipo FortiOS 'allowaccess: ping https ssh'.
        """
        if not actual:
            return True

        if isinstance(actual, str):
            actual_set: Set[str] = set(actual.lower().split())
        else:
            actual_set = {str(x).lower().strip() for x in actual}

        forbidden_set: Set[str] = {str(x).lower().strip() for x in forbidden_tokens}
        return len(actual_set.intersection(forbidden_set)) == 0

    @staticmethod
    def subset_of(actual: List[Any], allowed_list: List[Any]) -> bool:
        if not actual:
            return True
        actual_set = {str(x).strip().lower() for x in actual}
        allowed_set = {str(x).strip().lower() for x in allowed_list}
        return actual_set.issubset(allowed_set)

    @classmethod
    def evaluate(cls, operator_name: str, actual: Any, expected: Any) -> bool:
        handler = getattr(cls, operator_name, None)
        if not handler or operator_name.startswith("_") or operator_name == "evaluate":
            raise ValueError(f"Operador no soportado por el motor: '{operator_name}'")
        return handler(actual, expected)